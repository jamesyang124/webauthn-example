package handlers

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"time"

	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/types"
	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"

	session "github.com/jamesyang124/webauthn-example/internal/session"
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
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
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
	err := user.QueryUserByUsername(ctx, db, username, &userID, &username, &createDate)
	// if user not found, userID will be empty, and we proceed to create a new user
	if err != nil {
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
	sessionDataJson, err := util.MarshalAndRespondOnError(ctx, sessionData)
	if err != nil {
		return
	}
	if !session.SetWebauthnSessionDataWithErrorHandling(ctx, redisClient, sessionKey, sessionDataJson, 86400*time.Second) {
		return
	}

	responseJSON, err := util.MarshalAndRespondOnError(ctx, options)
	if err != nil {
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
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username and displayname using a helper
	username, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
	if err != nil {
		return
	}

	sessionKey := "webauthn_session:" + username
	var sessionData webauthn.SessionData
	// Get session data from Redis and parse directly
	redisSessionData, ok := session.GetWebauthnSessionDataWithErrorHandling(ctx, redisClient, sessionKey)
	if !ok {
		return
	}
	// Use json.Unmarshal directly for Redis string, as ParseJSONBody expects fasthttp.RequestCtx
	err = json.Unmarshal([]byte(redisSessionData), &sessionData)
	if err != nil {
		zap.L().Error("Error parsing session data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		return
	}

	zap.L().Info("Register verify sessionDataStr", zap.String("sessionDataStr", redisSessionData))

	// Extract "credential" from requestData as []byte
	credentialData, err := util.MarshalAndRespondOnError(ctx, requestData["credential"])
	if err != nil {
		return
	}

	// Extract webauthnUserID from credentialData
	var credentialMap map[string]interface{}
	if err := util.ParseJSONBody(ctx, &credentialMap); err != nil {
		zap.L().Error("Error unmarshaling credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
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
	err = user.QueryUserByUsername(ctx, db, username, &userID, &username, &createDate)
	if err != nil {
		return
	}

	// Create WebAuthnUser instance
	// Ensure this matches sessionData.UserID
	WebAuthnUser := &types.WebAuthnUser{
		ID:          string(sessionData.UserID),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	// Use sessionData in WebAuthn verification
	credential, err := webAuthn.FinishRegistration(WebAuthnUser, sessionData, &httpRequest)
	// credential.Flags {"userPresent":true,"userVerified":false,"backupEligible":true,"backupState":true}
	if err != nil {
		zap.L().Error("Error finishing WebAuthn registration", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Verification failed"}`)
		return
	}

	// Encode credential.PublicKey using standard Base64
	credentialPublicKeyEncoded := util.EncodeRawURLEncoding(credential.PublicKey)
	zap.L().Info("credentialPublicKeyEncoded", zap.String("credentialPublicKeyEncoded", credentialPublicKeyEncoded))

	credentialIdEncoded := util.EncodeRawURLEncoding(credential.ID)
	zap.L().Info("credentialIdEncoded", zap.String("credentialIdEncoded", credentialIdEncoded))

	// TOOD: may store credentials to another table
	// Persist credential data to the database using a helper
	result, err := user.UpdateUserWebauthnCredentials(ctx, db,
		WebAuthnUser.ID,
		credential.Authenticator.SignCount,
		credentialIdEncoded,
		credentialPublicKeyEncoded,
		username,
		username,
	)
	if err != nil {
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
	responseJSON, err := util.MarshalAndRespondOnError(ctx, responseData)
	if err != nil {
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)
}

// HandleAuthenticateOptions handles the WebAuthn authentication options
func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username and displayname using a helper
	username, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
	if err != nil {
		return
	}

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	// Query user by username and webauthn fields using repository helper
	err = user.QueryUserWebauthnByUsername(ctx, db, username, &userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		return
	}

	// Decode the credentialPublicKeyEncoded
	credentialPublicKey, ok := util.DecodeCredentialPublicKey(ctx, credentialPublicKeyEncoded)
	if !ok {
		return
	}

	credentialId, ok := util.DecodeCredentialID(ctx, credentialIdEncoded)
	if !ok {
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
	sessionDataJson, err := util.MarshalAndRespondOnError(ctx, sessionData)
	if err != nil {
		return
	}
	if !session.SetWebauthnSessionDataWithErrorHandling(ctx, redisClient, sessionKey, sessionDataJson, 86400*time.Second) {
		return
	}

	responseJSON, err := util.MarshalAndRespondOnError(ctx, options)
	if err != nil {
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
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username and displayname using a helper
	username, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
	if err != nil {
		return
	}

	sessionKey := "webauthn_login_session:" + username
	var sessionData webauthn.SessionData
	// Get session data from Redis and parse directly
	redisSessionData, ok := session.GetWebauthnSessionDataWithErrorHandling(ctx, redisClient, sessionKey)
	if !ok {
		return
	}
	err = json.Unmarshal([]byte(redisSessionData), &sessionData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		zap.L().Error("Error parsing session data", zap.Error(err))
		return
	}

	credentialData, err := util.MarshalAndRespondOnError(ctx, requestData["credential"])
	if err != nil {
		return
	}
	zap.L().Info("parsing credentialData", zap.ByteString("credentialData", credentialData))

	ctx.Request.SetBody(credentialData)
	// Now ctx.PostBody() will return the new body
	zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))

	var httpRequest http.Request
	fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)

	var userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded string
	// Query user by username and webauthn fields using repository helper
	err = user.QueryUserWebauthnByUsername(ctx, db, username, &userID, &webauthnUserID, &displayName, &credentialIdEncoded, &credentialPublicKeyEncoded)
	if err != nil {
		return
	}

	credentialId, ok := util.DecodeCredentialID(ctx, credentialIdEncoded)
	if !ok {
		return
	}

	credentialPublicKey, ok := util.DecodeCredentialPublicKey(ctx, credentialPublicKeyEncoded)
	if !ok {
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

	// Update the sign count in the database using a repository helper
	_, err = user.UpdateUserWebauthnSignCount(ctx, db, credential.Authenticator.SignCount, username)
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
	responseJSON, err := util.MarshalAndRespondOnError(ctx, responseData)
	if err != nil {
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)

	zap.L().Info("HandleAuthenticateVerification called successfully")
}
