// Package handlers provides HTTP handlers for WebAuthn authentication flows.
// It manages WebAuthn options and verification for registration and login.
// Uses PostgreSQL and Redis for persistence and session management.
// This package includes handler functions for registration and login flows,
// and utilities for session management and WebAuthn credential handling.
package handlers

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq" // Justify blank import: required for PostgreSQL driver registration

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-example/internal/session"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// HandleAuthenticateOptions handles the WebAuthn authentication options
func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username using a helper
	username, err := user.ValidateUsername(ctx, requestData)
	if err != nil {
		return
	}

	var userID, webauthnUserID, displayName, credentialIDEncoded, credentialPublicKeyEncoded string
	// Query user by username and webauthn fields using repository helper
	err = user.QueryUserWebauthnByUsername(
		ctx,
		db,
		username,
		&userID,
		&webauthnUserID,
		&displayName,
		&credentialIDEncoded,
		&credentialPublicKeyEncoded,
	)
	if err != nil {
		return
	}

	// Decode the credentialPublicKeyEncoded
	credentialPublicKey, ok := util.DecodeCredentialPublicKey(ctx, credentialPublicKeyEncoded)
	if !ok {
		return
	}

	// Decode the credentialIDEncoded
	credentialID, ok := util.DecodeCredentialID(ctx, credentialIDEncoded)
	if !ok {
		return
	}

	// Prepare webauthn user struct
	WebAuthnUser := util.NewWebAuthnUserWithCredential(
		webauthnUserID,
		username,
		displayName,
		credentialID,
		credentialPublicKey,
	)

	// Begin WebAuthn login
	options, sessionData, ok := util.BeginLogin(ctx, WebAuthnUser)
	if !ok {
		return
	}

	// Compose sessionDataJSON to related key
	sessionKey := "webauthn_login_session:" + username
	sessionDataJSON, err := util.MarshalAndRespondOnError(ctx, sessionData)
	if err != nil {
		return
	}

	// Persist sessionData to Redis with TTL
	if !session.SetWebauthnSessionDataWithErrorHandling(
		ctx,
		redisClient,
		sessionKey,
		sessionDataJSON,
		86400*time.Second,
	) {
		return
	}

	// Preparse response JSON
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
func HandleAuthenticateVerification(ctx *fasthttp.RequestCtx,
	db *sql.DB, redisClient *redis.Client) {
	// Parse JSON input
	var requestData map[string]interface{}
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username using a helper
	username, err := user.ValidateUsername(ctx, requestData)
	if err != nil {
		return
	}

	// Get session data from Redis and parse directly
	sessionKey := "webauthn_login_session:" + username
	var sessionData webauthn.SessionData
	redisSessionData, ok := session.GetWebauthnSessionDataWithErrorHandling(
		ctx,
		redisClient,
		sessionKey,
	)
	if !ok {
		return
	}

	// get session data from persistance
	if !util.UnmarshalAndRespondOnError(ctx, []byte(redisSessionData), &sessionData) {
		return
	}

	// fetch credential field from request JSON payload
	credentialData, err := util.MarshalAndRespondOnError(ctx, requestData["credential"])
	if err != nil {
		return
	}

	// adaption for different http request input type
	ctx.Request.SetBody(credentialData)
	httpRequest, err := util.ConvertFastHTTPToHTTPRequest(ctx)
	if err != nil {
		return
	}

	var userID, webauthnUserID, displayName, credentialIDEncoded, credentialPublicKeyEncoded string
	// Query user by username and webauthn fields using repository helper
	err = user.QueryUserWebauthnByUsername(
		ctx,
		db,
		username,
		&userID,
		&webauthnUserID,
		&displayName,
		&credentialIDEncoded,
		&credentialPublicKeyEncoded,
	)
	if err != nil {
		return
	}

	credentialID, ok := util.DecodeCredentialID(ctx, credentialIDEncoded)
	if !ok {
		return
	}

	credentialPublicKey, ok := util.DecodeCredentialPublicKey(ctx, credentialPublicKeyEncoded)
	if !ok {
		return
	}

	// should get values from db tables
	WebAuthnUser := util.NewWebAuthnUserWithBackupEligible(
		webauthnUserID,
		username,
		displayName,
		credentialID,
		credentialPublicKey,
		true, // BackupEligible
	)

	// Finish WebAuthn login
	credential, ok := util.FinishLogin(ctx, WebAuthnUser, sessionData, httpRequest)
	if !ok {
		return
	}

	// Update the sign count in the database using a repository helper
	_, err = user.UpdateUserWebauthnSignCount(
		ctx,
		db,
		credential.Authenticator.SignCount,
		username,
	)
	if err != nil {
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
