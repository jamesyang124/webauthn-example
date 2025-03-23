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
	"github.com/google/uuid"                    // Add this import for generating random text
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
		// RPOrigins should be FE server host
		RPOrigins: []string{"http://localhost:5173"},
		//		RPOrigins: []string{"http://localhost:8080"},
	})
	if err != nil {
		log.Fatalf("failed to create WebAuthn instance: %v", err)
	}
}

func HandleRegisterOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		ctx.Logger().Printf("Error unmarshaling JSON payload: %s", err)
		return
	}

	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		ctx.Logger().Printf("Invalid or missing username in JSON payload")
		return
	}

	var userID, createDate string

	err := db.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.Error("WebAuthnUser not found or invalid password", fasthttp.StatusUnauthorized)
		} else {
			ctx.Error("Database query error", fasthttp.StatusInternalServerError)
		}
		ctx.Logger().Printf("Error in HandleAuthenticate: %s", err)
		return
	}

	// Generate random text for webauthnUserID if it is empty
	webauthnUserID, err := uuid.NewV7()
	if err != nil {
		ctx.Logger().Printf("Error to generate webauthn user id uuidv7: %s", err)
	}

	WebAuthnUser := &types.WebAuthnUser{ // Use the imported WebAuthnUser type
		ID:          webauthnUserID.String(),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	// TODO: _ is sessionData shold persist in later block
	options, sessionData, err := webAuthn.BeginRegistration(WebAuthnUser)
	if err != nil {
		ctx.Error("Failed to begin WebAuthn registration", fasthttp.StatusInternalServerError)
		ctx.Logger().Printf("Error beginning WebAuthn registration: %s", err)
		return
	}

	// Persist sessionData to Redis with TTL
	sessionKey := "webauthn_session:" + username
	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		ctx.Error("Failed to marshal sessionData", fasthttp.StatusInternalServerError)
		ctx.Logger().Printf("Error marshaling sessionData: %s", err)
		return
	}
	ctx.Logger().Printf("register options sessionData: %s", sessionDataJson)

	err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
	if err != nil {
		ctx.Error("Failed to persist session data", fasthttp.StatusInternalServerError)
		ctx.Logger().Printf("Error persisting session data: %s", err)
		return
	}

	responseJSON, err := json.Marshal(options)
	if err != nil {
		ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
		ctx.Logger().Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	ctx.Logger().Printf("HandleRegister called")
}

func HandleRegisterVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		ctx.Logger().Printf("Error unmarshaling JSON payload: %s", err)
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
			ctx.Logger().Printf("Error retrieving session data: %s", err)
		}
		return
	}

	err = json.Unmarshal([]byte(sessionDataStr), &sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		ctx.Logger().Printf("Error parsing session data: %s", err)
		return
	}

	ctx.Logger().Printf("Register verify sessionDataStr: %s", sessionDataStr)

	// Extract "credential" from requestData as []byte
	credentialData, err := json.Marshal(requestData["credential"])
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		ctx.Logger().Printf("Error marshaling credential data: %s", err)
		return
	}

	// Extract webauthnUserID from credentialData
	var credentialMap map[string]interface{}
	if err := json.Unmarshal(credentialData, &credentialMap); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data structure"}`)
		ctx.Logger().Printf("Error unmarshaling credential data: %s", err)
		return
	}

	// Override ctx.PostBody with the extracted credential data
	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	ctx.Logger().Printf("Overridden PostBody: %s", string(ctx.PostBody()))

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
		ctx.Logger().Printf("Error in HandleAuthenticate: %s", err)
		return
	}

	WebAuthnUser := &types.WebAuthnUser{ // Use the imported WebAuthnUser type
		ID:          string(sessionData.UserID), // Ensure this matches sessionData.UserID
		Name:        username,
		DisplayName: displayname,
		Credentials: []webauthn.Credential{},
	}

	// Use sessionData in WebAuthn verification
	credential, err := webAuthn.FinishRegistration(WebAuthnUser, sessionData, &httpRequest)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Verification failed"}`)
		ctx.Logger().Printf("Error finishing WebAuthn registration: %s", err)
		return
	}
	// credential.Flags {"userPresent":true,"userVerified":false,"backupEligible":true,"backupState":true}

	// Encode credential.PublicKey using standard Base64
	credentialPublicKeyEncoded := base64.RawURLEncoding.EncodeToString(credential.PublicKey)
	ctx.Logger().Printf(credentialPublicKeyEncoded)

	credentialIdEncoded := base64.RawURLEncoding.EncodeToString(credential.ID)
	ctx.Logger().Printf(credentialIdEncoded)

	// TOOD: may store credentials to another table

	// Persist credential data to the database
	result, err := db.Exec(
		`UPDATE users SET webauthn_user_id = $1, webauthn_sign_count = $2, webauthn_credential_id = $3, webauthn_credential_public_key = $4, webauthn_displayname = $5 WHERE username = $6`,
		WebAuthnUser.ID,
		credential.Authenticator.SignCount,
		credentialIdEncoded,
		credentialPublicKeyEncoded, // Use the decoded public key
		displayname,
		username,
	)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		ctx.Logger().Printf("Error persisting credential data: %s", err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		ctx.Logger().Printf("Error persisting credential data: %s", err)
		return
	}
	ctx.Logger().Printf("rows affected: %d", rowsAffected)

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

func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		ctx.Logger().Printf("Error unmarshaling JSON payload: %s", err)
		return
	}

	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		ctx.Logger().Printf("Invalid or missing username in JSON payload")
		return
	}

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	err := db.QueryRow("SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1", username).Scan(&userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		ctx.Logger().Printf("Error querying user: %s", err)
		return
	}

	// Decode the credentialPublicKeyEncoded
	credentialPublicKey, err := base64.RawURLEncoding.DecodeString(credentialPublicKeyEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode public key"}`)
		ctx.Logger().Printf("Error decoding public key: %s", err)
		return
	}

	credentialId, err := base64.RawURLEncoding.DecodeString(credentialIdEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode webauthn credential id"}`)
		ctx.Logger().Printf("Error decoding webauthn credential id: %s", err)
		return
	}

	WebAuthnUser := &types.WebAuthnUser{
		ID:          webauthnUserID,
		Name:        username,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{
			{
				ID:        credentialId,
				PublicKey: credentialPublicKey,
			},
		},
	}

	options, sessionData, err := webAuthn.BeginLogin(WebAuthnUser)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to begin WebAuthn login"}`)
		ctx.Logger().Printf("Error beginning WebAuthn login: %s", err)
		return
	}

	// Persist sessionData to Redis with TTL
	sessionKey := "webauthn_login_session:" + username
	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal session data"}`)
		ctx.Logger().Printf("Error marshaling session data: %s", err)
		return
	}
	ctx.Logger().Printf("auth options sessionData: %s", sessionDataJson)

	err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist session data"}`)
		ctx.Logger().Printf("Error persisting session data: %s", err)
		return
	}

	responseJSON, err := json.Marshal(options)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal response"}`)
		ctx.Logger().Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	ctx.Logger().Printf("HandleBeginLogin called")
}

func HandleAuthenticateVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		ctx.Logger().Printf("Error unmarshaling JSON payload: %s", err)
		return
	}

	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		ctx.Logger().Printf("Invalid or missing username in JSON payload")
		return
	}

	sessionKey := "webauthn_login_session:" + username
	var sessionData webauthn.SessionData
	sessionDataStr, err := redisClient.Get(context.Background(), sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Session data not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Failed to retrieve session data"}`)
			ctx.Logger().Printf("Error retrieving session data: %s", err)
		}
		return
	}

	err = json.Unmarshal([]byte(sessionDataStr), &sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		ctx.Logger().Printf("Error parsing session data: %s", err)
		return
	}

	credentialData, err := json.Marshal(requestData["credential"])
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		ctx.Logger().Printf("Error marshaling credential data: %s", err)
		return
	}
	ctx.Logger().Printf("parsing credentialData: %s", credentialData)

	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	ctx.Logger().Printf("Overridden PostBody: %s", string(ctx.PostBody()))

	var httpRequest http.Request
	fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	err = db.QueryRow("SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1", username).Scan(&userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		ctx.Logger().Printf("Error querying user: %s", err)
		return
	}

	credentialId, err := base64.RawURLEncoding.DecodeString(credentialIdEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode webauthn credential id"}`)
		ctx.Logger().Printf("Error decoding webauthn credential id: %s", err)
		return
	}

	credentialPublicKey, err := base64.RawURLEncoding.DecodeString(credentialPublicKeyEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode public key"}`)
		ctx.Logger().Printf("Error decoding public key: %s", err)
		return
	}

	// should get values from db tables
	WebAuthnUser := &types.WebAuthnUser{
		ID:          webauthnUserID,
		Name:        username,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{
			{
				ID:        credentialId,
				PublicKey: credentialPublicKey,
				Flags: webauthn.CredentialFlags{
					// allow multi-device auth
					BackupEligible: true,
				},
			},
		},
	}

	credential, err := webAuthn.FinishLogin(WebAuthnUser, sessionData, &httpRequest)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Login verification failed"}`)
		ctx.Logger().Printf("Error finishing WebAuthn login: %s", err)
		return
	}

	// Update the sign count in the database
	_, err = db.Exec(
		`UPDATE users SET webauthn_sign_count = $1 WHERE username = $2`,
		credential.Authenticator.SignCount,
		username,
	)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to update sign count"}`)
		ctx.Logger().Printf("Error updating sign count: %s", err)
		return
	}

	// Respond with success
	responseData := map[string]interface{}{
		"message": "Login verification successful",
		"user":    WebAuthnUser,
	}
	responseJSON, _ := json.Marshal(responseData)

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	ctx.Logger().Printf("HandleAuthenticateVerification called successfully")
}
