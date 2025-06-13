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
	"github.com/google/uuid"
	"github.com/jamesyang124/webauthn-example/types"
	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"
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
		// RPOrigins: []string{"http://localhost:5173"},
		RPOrigins: []string{"http://localhost:8080"},
	})
	if err != nil {
		log.Fatalf("failed to create WebAuthn instance: %v", err)
	}
}

// HandleRegisterOptions handles the WebAuthn registration options
func HandleRegisterOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		types.RespondWithError(ctx, fasthttp.StatusBadRequest, "Invalid JSON", "Error unmarshaling JSON payload", err)
		return
	}

	// Validate username
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		types.RespondWithError(ctx, fasthttp.StatusBadRequest, "Username is required and must be a string", "Invalid or missing username in JSON payload")
		return
	}

	var userID, createDate string

	// Query user by username
	err := db.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &createDate)
	// err := db.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			types.RespondWithError(ctx, fasthttp.StatusUnauthorized, "WebAuthnUser not found or invalid password", "WebAuthnUser not found or invalid password", err)
		} else {
			types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Database query error", "Database query error", err)
		}
		return
	}

	// Generate random text for webauthnUserID if it is empty
	webauthnUserID, err := uuid.NewV7()
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Error to generate webauthn user id uuidv7", "Error to generate webauthn user id uuidv7", err)
	}

	// Create WebAuthnUser instance
	WebAuthnUser := &types.WebAuthnUser{
		ID:          webauthnUserID.String(),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	// TODO: _ is sessionData shold persist in later block
	options, sessionData, err := webAuthn.BeginRegistration(WebAuthnUser)
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Failed to begin WebAuthn registration", "Error beginning WebAuthn registration", err)
		return
	}

	// Persist sessionData to Redis with TTL
	sessionKey := "webauthn_session:" + username
	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Failed to marshal sessionData", "Error marshaling sessionData", err)
		return
	}
	zap.L().Info("register options sessionData", zap.ByteString("sessionData", sessionDataJson))

	err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Failed to persist session data", "Error persisting session data", err)
		return
	}

	responseJSON, err := json.Marshal(options)
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Failed to marshal response", "Error marshaling response", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	zap.L().Info("HandleRegister called")
}

// HandleRegisterVerification handles the verification of WebAuthn registration
func HandleRegisterVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		zap.L().Error("Error unmarshaling JSON payload", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		return
	}

	// Validate username
	username, ok := requestData["username"].(string)
	if !ok {
		zap.L().Error("Invalid username type")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid username type"}`)
		return
	}

	displayname, ok := requestData["displayname"].(string)
	if !ok {
		zap.L().Error("Invalid displayname type")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid displayname type"}`)
		return
	}

	sessionKey := "webauthn_session:" + username
	var sessionData webauthn.SessionData
	sessionDataStr, err := redisClient.Get(context.Background(), sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			zap.L().Error("Session data not found", zap.String("username", username))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Session data not found"}`)
		} else {
			zap.L().Error("Error retrieving session data", zap.Error(err))
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Failed to retrieve session data"}`)
		}
		return
	}

	err = json.Unmarshal([]byte(sessionDataStr), &sessionData)
	if err != nil {
		zap.L().Error("Error parsing session data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		return
	}

	zap.L().Info("Register verify sessionDataStr", zap.String("sessionDataStr", sessionDataStr))

	// Extract "credential" from requestData as []byte
	credentialData, err := json.Marshal(requestData["credential"])
	if err != nil {
		zap.L().Error("Error marshaling credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		return
	}

	// Extract webauthnUserID from credentialData
	var credentialMap map[string]interface{}
	if err := json.Unmarshal(credentialData, &credentialMap); err != nil {
		zap.L().Error("Error unmarshaling credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data structure"}`)
		return
	}

	// Override ctx.PostBody with the extracted credential data
	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))

	var httpRequest http.Request
	fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)

	var userID, createDate string

	// Query user by username
	err = db.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			types.RespondWithError(ctx, fasthttp.StatusUnauthorized, "WebAuthnUser not found or invalid password", "WebAuthnUser not found or invalid password", err)
		} else {
			types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Database query error", "Database query error", err)
		}
		zap.L().Error("Error in HandleAuthenticate", zap.Error(err))
		return
	}

	// Create WebAuthnUser instance
	// Ensure this matches sessionData.UserID
	WebAuthnUser := &types.WebAuthnUser{
		ID:          string(sessionData.UserID),
		Name:        username,
		DisplayName: displayname,
		Credentials: []webauthn.Credential{},
	}

	// Use sessionData in WebAuthn verification
	credential, err := webAuthn.FinishRegistration(WebAuthnUser, sessionData, &httpRequest)
	if err != nil {
		zap.L().Error("Error finishing WebAuthn registration", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Verification failed"}`)
		return
	}
	// credential.Flags {"userPresent":true,"userVerified":false,"backupEligible":true,"backupState":true}

	// Encode credential.PublicKey using standard Base64
	credentialPublicKeyEncoded := base64.RawURLEncoding.EncodeToString(credential.PublicKey)
	zap.L().Info("credentialPublicKeyEncoded", zap.String("credentialPublicKeyEncoded", credentialPublicKeyEncoded))

	credentialIdEncoded := base64.RawURLEncoding.EncodeToString(credential.ID)
	zap.L().Info("credentialIdEncoded", zap.String("credentialIdEncoded", credentialIdEncoded))

	// TOOD: may store credentials to another table
	// Persist credential data to the database
	result, err := db.Exec(
		`UPDATE users SET webauthn_user_id = $1, webauthn_sign_count = $2, webauthn_credential_id = $3, webauthn_credential_public_key = $4, webauthn_displayname = $5 WHERE username = $6`,
		WebAuthnUser.ID,
		credential.Authenticator.SignCount,
		credentialIdEncoded,
		credentialPublicKeyEncoded,
		displayname,
		username,
	)

	if err != nil {
		zap.L().Error("Error persisting credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		zap.L().Error("Error persisting credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		return
	}
	zap.L().Info("rows affected", zap.Int64("rowsAffected", rowsAffected))

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

// HandleAuthenticateOptions handles the WebAuthn authentication options
func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		zap.L().Error("Error unmarshaling JSON payload", zap.Error(err))
		return
	}

	// Validate username
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		zap.L().Error("Invalid or missing username in JSON payload")
		return
	}

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	// Query user by username
	err := db.QueryRow("SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1", username).Scan(&userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		zap.L().Error("Error querying user: %s", zap.Error(err))
		return
	}

	// Decode the credentialPublicKeyEncoded
	credentialPublicKey, err := base64.RawURLEncoding.DecodeString(credentialPublicKeyEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode public key"}`)
		zap.L().Error("Error decoding public key", zap.Error(err))
		return
	}

	credentialId, err := base64.RawURLEncoding.DecodeString(credentialIdEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode webauthn credential id"}`)
		zap.L().Error("Error decoding webauthn credential id", zap.Error(err))
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

	// Begin WebAuthn login
	options, sessionData, err := webAuthn.BeginLogin(WebAuthnUser)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to begin WebAuthn login"}`)
		zap.L().Error("Error beginning WebAuthn login", zap.Error(err))
		return
	}

	// Persist sessionData to Redis with TTL
	sessionKey := "webauthn_login_session:" + username
	sessionDataJson, err := json.Marshal(sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal session data"}`)
		zap.L().Error("Error marshaling session data", zap.Error(err))
		return
	}
	zap.L().Info("auth options sessionData", zap.ByteString("sessionData", sessionDataJson))

	err = redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), 86400*time.Second).Err()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist session data"}`)
		zap.L().Error("Error persisting session data", zap.Error(err))
		return
	}

	responseJSON, err := json.Marshal(options)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to marshal response"}`)
		zap.L().Error("Error marshaling response", zap.Error(err))
		return
	}

	// Set response content type and status for successful login
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	zap.L().Info("HandleBeginLogin called")
}

// HandleAuthenticateVerification processes the verification of WebAuthn authentication
func HandleAuthenticateVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestData); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid JSON"}`)
		zap.L().Error("Error unmarshaling JSON payload", zap.Error(err))
		return
	}

	// Validate username
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		zap.L().Error("Invalid or missing username in JSON payload")
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
			zap.L().Error("Error retrieving session data", zap.Error(err))
		}
		return
	}

	err = json.Unmarshal([]byte(sessionDataStr), &sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		zap.L().Error("Error parsing session data", zap.Error(err))
		return
	}

	credentialData, err := json.Marshal(requestData["credential"])
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		zap.L().Error("Error marshaling credential data", zap.Error(err))
		return
	}
	zap.L().Info("parsing credentialData", zap.ByteString("credentialData", credentialData))

	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))

	var httpRequest http.Request
	fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	// Query user by username
	err = db.QueryRow("SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1", username).Scan(&userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		zap.L().Error("Error querying user: %s", zap.Error(err))
		return
	}

	credentialId, err := base64.RawURLEncoding.DecodeString(credentialIdEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode webauthn credential id"}`)
		zap.L().Error("Error decoding webauthn credential id", zap.Error(err))
		return
	}

	credentialPublicKey, err := base64.RawURLEncoding.DecodeString(credentialPublicKeyEncoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode public key"}`)
		zap.L().Error("Error decoding public key", zap.Error(err))
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

	// Finish WebAuthn login
	credential, err := webAuthn.FinishLogin(WebAuthnUser, sessionData, &httpRequest)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Login verification failed"}`)
		zap.L().Error("Error finishing WebAuthn login", zap.Error(err))
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
		zap.L().Error("Error updating sign count", zap.Error(err))
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

	zap.L().Info("HandleAuthenticateVerification called successfully")
}
