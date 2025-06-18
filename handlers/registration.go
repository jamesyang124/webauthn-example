// Package handlers provides HTTP handlers for WebAuthn registration and authentication.
// It manages WebAuthn options and verification for registration and login.
// Uses PostgreSQL and Redis for persistence and session management.
// This package includes handler functions for registration and login flows,
// and utilities for session management and WebAuthn credential handling.
package handlers

import (
	"database/sql"
	"net/http"
	"time"

	_ "github.com/lib/pq" // Justify blank import: required for PostgreSQL driver registration

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	session "github.com/jamesyang124/webauthn-example/internal/session"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/internal/weberror"
	fasthttp "github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"
)

// HandleRegisterOptions handles the WebAuthn registration options
func HandleRegisterOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	var username string
	// Parse request JSON body into map
	if _, err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username from request data
	_, _ = user.ValidateUsername(ctx, requestData, &username)

	var userID, createDate string
	// Query user by username from database
	err := user.QueryUserByUsername(db, username, &userID, &username, &createDate)
	if err != nil {
		if appErr, ok := err.(*weberror.AppError); ok {
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		} else {
			appErr := weberror.UnexpectedError(err, "QueryUserByUsername")
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		}
		return
	}

	// Generate new UUID for WebAuthn user ID
	webauthnUserID, err := uuid.NewV7()
	if err != nil {
		appErr := weberror.UUIDGenerationError(err)
		httpErr := weberror.ToHTTPError(appErr)
		httpErr.RespondAndLog(ctx)
		return
	}

	// Create new WebAuthn user struct
	WebAuthnUser := util.NewWebAuthnUser(
		webauthnUserID.String(),
		username,
		username,
	)

	// Begin WebAuthn registration process
	options, sessionData, ok := util.BeginRegistration(ctx, WebAuthnUser)
	if !ok {
		return
	}

	sessionKey := "webauthn_session:" + username
	// Marshal session data to JSON
	sessionDataJSON, err := util.MarshalAndRespondOnError(ctx, sessionData)
	if err != nil {
		return
	}
	// Store session data in Redis with TTL
	_, err = session.SetWebauthnSessionData(ctx, redisClient, sessionKey, sessionDataJSON, 86400*time.Second)

	if err != nil {
		return
	}

	// Marshal registration options for response
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
	var requestData map[string]interface{}
	// Parse request JSON body into map
	if _, err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	// Validate username and display name from request
	username, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
	if err != nil {
		return
	}

	sessionKey := "webauthn_session:" + username
	var sessionData webauthn.SessionData
	// Retrieve session data from Redis
	redisSessionData, _ := session.GetWebauthnSessionData(
		ctx,
		redisClient,
		sessionKey,
	)
	// Unmarshal session data from JSON
	_, _ = util.UnmarshalAndRespondOnError(ctx, []byte(redisSessionData), &sessionData)

	zap.L().Info("Register verify sessionDataStr", zap.String("sessionDataStr", redisSessionData))

	// Marshal credential data from request
	credentialData, err := util.MarshalAndRespondOnError(ctx, requestData["credential"])
	if err != nil {
		return
	}

	var credentialMap map[string]interface{}

	// Parse credential data as JSON
	if _, err := util.ParseJSONBody(ctx, &credentialMap); err != nil {
		appErr := weberror.CredentialDataInvalidError(err)
		httpErr := weberror.ToHTTPError(appErr)
		httpErr.RespondAndLog(ctx)
		return
	}

	ctx.Request.SetBody(credentialData)
	zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))

	var httpRequest http.Request
	// Convert FastHTTP request to standard HTTP request
	err = fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to convert request"}`)
		zap.L().Error("Error converting fasthttp request", zap.Error(err))
		return
	}

	var userID, createDate string
	// Query user by username from database
	err = user.QueryUserByUsername(db, username, &userID, &username, &createDate)
	if err != nil {
		if appErr, ok := err.(*weberror.AppError); ok {
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		} else {
			appErr := weberror.UnexpectedError(err, "QueryUserByUsername")
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		}
		return
	}

	// Create WebAuthn user with session data
	WebAuthnUser := util.NewWebAuthnUser(
		string(sessionData.UserID),
		username,
		username,
	)

	// Finish WebAuthn registration process
	credential, ok := util.FinishRegistration(ctx, WebAuthnUser, sessionData, &httpRequest)
	if !ok {
		return
	}

	// Encode credential public key for storage
	credentialPublicKeyEncoded := util.EncodeRawURLEncoding(credential.PublicKey)
	zap.L().Info("credentialPublicKeyEncoded", zap.String("credentialPublicKeyEncoded", credentialPublicKeyEncoded))

	// Encode credential ID for storage
	credentialIDEncoded := util.EncodeRawURLEncoding(credential.ID)
	zap.L().Info("credentialIDEncoded", zap.String("credentialIDEncoded", credentialIDEncoded))

	// Update user with WebAuthn credentials in database
	result, err := user.UpdateUserWebauthnCredentials(db,
		WebAuthnUser.ID,
		credential.Authenticator.SignCount,
		credentialIDEncoded,
		credentialPublicKeyEncoded,
		username,
		username,
	)
	if err != nil {
		if appErr, ok := err.(*weberror.AppError); ok {
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		} else {
			appErr := weberror.UnexpectedError(err, "UpdateUserWebauthnCredentials")
			httpErr := weberror.ToHTTPError(appErr)
			httpErr.RespondAndLog(ctx)
		}
		return
	}

	// Check number of rows affected by update
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		zap.L().Error("Error persisting credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		return
	}
	zap.L().Info("rows affected", zap.Int64("rowsAffected", rowsAffected))

	responseData := map[string]interface{}{
		"credential": credential,
		"payload":    requestData,
		"message":    "Verification successful",
		"path":       string(ctx.Path()),
	}
	// Marshal final response data
	responseJSON, err := util.MarshalAndRespondOnError(ctx, responseData)
	if err != nil {
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(responseJSON)
}
