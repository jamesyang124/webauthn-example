package examples

import (
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"time"

	"net/http"

	"encoding/base64"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-go/types" // Import the types package
	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

var (
	webAuthn     *webauthn.WebAuthn
	registerTmpl *template.Template
)

func init() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Example Corp",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		log.Fatalf("failed to create WebAuthn instance: %v", err)
	}

	registerTmpl, err = template.ParseFiles("templates/register.html.tmpl")
	if err != nil {
		log.Fatalf("failed to parse HTML template: %v", err)
	}
}

func HandleRegisterOptions(db *sql.DB, logger *log.Logger, redisClient *redis.Client) func(*fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		var requestData map[string]interface{}
		if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Invalid JSON"}`)
			logger.Printf("Error unmarshaling JSON payload: %s", err)
			return
		}

		username, ok := requestData["username"].(string)
		if !ok || username == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
			logger.Println("Invalid or missing username in JSON payload")
			return
		}

		var userID, webauthnID, createDate string

		err := db.QueryRow("SELECT id, username, COALESCE(webauthn_id, ''), created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &webauthnID, &createDate)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.Error("WebAuthnUser not found or invalid password", fasthttp.StatusUnauthorized)
			} else {
				ctx.Error("Database query error", fasthttp.StatusInternalServerError)
			}
			logger.Printf("Error in HandleAuthenticate: %s", err)
			return
		}

		WebAuthnUser := &types.WebAuthnUser{ // Use the imported WebAuthnUser type
			ID:          webauthnID,
			Name:        username,
			DisplayName: username,
			Credentials: []webauthn.Credential{},
		}

		// TODO: _ is sessionData shold persist in later block
		options, sessionData, err := webAuthn.BeginRegistration(WebAuthnUser)
		if err != nil {
			ctx.Error("Failed to begin WebAuthn registration", fasthttp.StatusInternalServerError)
			logger.Printf("Error beginning WebAuthn registration: %s", err)
			return
		}

		// Persist sessionData to Redis with TTL
		sessionKey := "webauthn_session:" + username
		sessionDataJson, err := json.Marshal(sessionData)
		if err != nil {
			ctx.Error("Failed to marshal sessionData", fasthttp.StatusInternalServerError)
			logger.Printf("Error marshaling sessionData: %s", err)
			return
		}
		err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
		if err != nil {
			ctx.Error("Failed to persist session data", fasthttp.StatusInternalServerError)
			logger.Printf("Error persisting session data: %s", err)
			return
		}

		responseJSON, err := json.Marshal(options)
		if err != nil {
			ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
			logger.Printf("Error marshaling response: %s", err)
			return
		}

		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(responseJSON)

		logger.Println("HandleRegister called")
	}
}

func HandleRegisterVerification(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		return
	}

	username, ok := requestData["username"].(string)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid username type"}`)
		return
	}

	displayname, ok := requestData["displayname"].(string)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid displayname type"}`)
		return
	}

	sessionKey := "webauthn_session:" + username
	var sessionData webauthn.SessionData
	sessionDataStr, err := redisClient.Get(context.Background(), sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Session data not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Failed to retrieve session data"}`)
			logger.Printf("Error retrieving session data: %s", err)
		}
		return
	}

	err = json.Unmarshal([]byte(sessionDataStr), &sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		logger.Printf("Error parsing session data: %s", err)
		return
	}

	// Extract "credential" from requestData as []byte
	credentialData, err := json.Marshal(requestData["credential"])
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		logger.Printf("Error marshaling credential data: %s", err)
		return
	}

	// Extract webauthnID from credentialData
	var credentialMap map[string]interface{}
	if err := json.Unmarshal(credentialData, &credentialMap); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data structure"}`)
		logger.Printf("Error unmarshaling credential data: %s", err)
		return
	}

	// Override ctx.PostBody with the extracted credential data
	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	logger.Printf("Overridden PostBody: %s", string(ctx.PostBody()))

	var httpRequest http.Request
	fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)

	var userID, createDate string

	err = db.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.Error("WebAuthnUser not found or invalid password", fasthttp.StatusUnauthorized)
		} else {
			ctx.Error("Database query error", fasthttp.StatusInternalServerError)
		}
		logger.Printf("Error in HandleAuthenticate: %s", err)
		return
	}

	WebAuthnUser := &types.WebAuthnUser{ // Use the imported WebAuthnUser type
		ID:          string(sessionData.UserID),
		Name:        username,
		DisplayName: displayname,
		Credentials: []webauthn.Credential{},
	}

	// Use sessionData in WebAuthn verification
	credential, err := webAuthn.FinishRegistration(WebAuthnUser, sessionData, &httpRequest)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Verification failed"}`)
		logger.Printf("Error finishing WebAuthn registration: %s", err)
		return
	}
	logger.Println(WebAuthnUser)

	// Encode credential.PublicKey using standard Base64
	credentialPublicKeyEncoded := base64.StdEncoding.EncodeToString(credential.PublicKey)
	logger.Println(credentialPublicKeyEncoded)

	credentialIdEncoded := base64.StdEncoding.EncodeToString(credential.ID)
	logger.Println(credentialIdEncoded)

	// Persist credential data to the database
	result, err := db.Exec(
		`UPDATE users SET webauthn_id = $1, webauthn_sign_count = $2, webauthn_public_key = $3, webauthn_displayname = $4 WHERE username = $5`,
		credentialIdEncoded,
		credential.Authenticator.SignCount,
		credentialPublicKeyEncoded, // Use the decoded public key
		displayname,
		username,
	)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		logger.Printf("Error persisting credential data: %s", err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		logger.Printf("Error persisting credential data: %s", err)
		return
	}
	logger.Printf("rows affected: %d", rowsAffected)

	// Respond with JSON
	responseData := map[string]interface{}{
		"credential": credential,
		"payload":    requestData,
		"message":    "Verification successful",
		"path":       string(ctx.Path()),
	}
	responseJSON, _ := json.Marshal(responseData)

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)
}

func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger, redisClient *redis.Client) {
	username := string(ctx.FormValue("username"))
	if username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required"}`)
		return
	}

	var userID, webauthnID, displayName string
	err := db.QueryRow("SELECT id, webauthn_id, webauthn_displayname FROM users WHERE username=$1", username).Scan(&userID, &webauthnID, &displayName)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		logger.Printf("Error querying user: %s", err)
		return
	}

	WebAuthnUser := &types.WebAuthnUser{
		ID:          webauthnID,
		Name:        username,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{},
	}

	options, sessionData, err := webAuthn.BeginLogin(WebAuthnUser)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to begin WebAuthn login"}`)
		logger.Printf("Error beginning WebAuthn login: %s", err)
		return
	}

	// Persist sessionData to Redis with TTL
	sessionKey := "webauthn_login_session:" + username
	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal session data"}`)
		logger.Printf("Error marshaling session data: %s", err)
		return
	}
	err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist session data"}`)
		logger.Printf("Error persisting session data: %s", err)
		return
	}

	responseJSON, err := json.Marshal(options)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal response"}`)
		logger.Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	logger.Println("HandleBeginLogin called")
}

func HandleAuthenticateVerification(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger) {
	//username := string(ctx.FormValue("username"))

	responseJSON, err := json.Marshal("")
	if err != nil {
		ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
		logger.Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(string(responseJSON))

	logger.Println("HandleAuthenticate called")
}
