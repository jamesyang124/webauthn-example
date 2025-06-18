// Package handlers provides HTTP handlers for WebAuthn authentication flows.
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
	"github.com/jamesyang124/webauthn-example/internal/session"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// HandleAuthenticateOptions handles the WebAuthn authentication options using TryIO monad chains
func HandleAuthenticateOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Shared variables for the chain
	var (
		requestData                                     map[string]interface{}
		username, userID, displayName, webauthnUserID   string
		credentialIDEncoded, credentialPublicKeyEncoded string
		credentialPublicKey                             []byte
		loginResponse                                   types.BeginLoginResponse
	)

	// Parse request JSON body into map
	types.NewTryIO(func() (string, error) {
		return util.ParseJSONBody(ctx, &requestData)
	}).
		// Validate username from request data
		ThenString(func(_ string) (string, error) {
			return user.ValidateUsername(ctx, requestData, &username)
		}).
		// Query user WebAuthn data from database
		ThenString(func(validatedUsername string) (string, error) {
			return user.QueryUserWebauthnByUsername(
				db, username,
				&userID, &webauthnUserID, &displayName,
				&credentialIDEncoded, &credentialPublicKeyEncoded,
			)
		}).
		// Decode base64 encoded credential public key
		ThenBytes(func(_ string) ([]byte, error) {
			return util.DecodeCredentialPublicKey(
				ctx, credentialPublicKeyEncoded,
				&credentialPublicKey,
			)
		}).
		// Decode base64 encoded credential ID
		ThenBytes(func(pubKey []byte) ([]byte, error) {
			return util.DecodeCredentialID(ctx, credentialIDEncoded)
		}).
		// Create WebAuthn user with decoded credentials
		ThenWebAuthnUser(func(credentialID []byte) (*types.WebAuthnUser, error) {
			return util.NewWebAuthnUserWithCredential(
				webauthnUserID, username, displayName,
				credentialID, credentialPublicKey,
			)
		}).
		// Begin WebAuthn login process and generate options
		ThenBeginLoginResponse(func(webAuthnUser *types.WebAuthnUser) (*types.BeginLoginResponse, error) {
			return util.BeginLogin(ctx, webAuthnUser, &loginResponse)
		}).
		// Marshal session data to JSON
		ThenBytes(func(loginResponseData *types.BeginLoginResponse) ([]byte, error) {
			return util.MarshalAndRespondOnError(ctx, loginResponse.SessionData)
		}).
		// Store session data in Redis with TTL
		ThenBytes(func(sessionDataJSON []byte) ([]byte, error) {
			return session.SetWebauthnSessionData(
				ctx, redisClient,
				"webauthn_login_session:"+username,
				sessionDataJSON, 86400*time.Second,
			)
		}).
		// Marshal login options for client response
		ThenBytes(func(_ []byte) ([]byte, error) {
			return util.MarshalAndRespondOnError(ctx, loginResponse.Options)
		}).
		Match(
			func(err error) {
				// Handle error through weberror system
				if appErr, ok := err.(*weberror.AppError); ok {
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
				} else {
					// Fallback for unexpected errors
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					ctx.SetContentType("application/json")
					ctx.SetBodyString(`{"error": "Internal server error"}`)
					zap.L().Error(
						"Unexpected error in HandleAuthenticateOptions",
						zap.Error(err),
					)
				}
			},
			func(responseJSON []byte) {
				// Send success response
				ctx.SetContentType("application/json")
				ctx.SetStatusCode(fasthttp.StatusOK)
				ctx.SetBody(responseJSON)
			},
		)
}

// HandleAuthenticateVerification processes the verification of WebAuthn authentication using a TryIO monad chain
func HandleAuthenticateVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {

	var (
		credentialID, credentialPublicKey               []byte
		requestData                                     map[string]interface{}
		username, userID, webauthnUserID, displayName   string
		credentialIDEncoded, credentialPublicKeyEncoded string
		sessionData                                     webauthn.SessionData
		WebAuthnUser                                    types.WebAuthnUser
		convertedRequest                                http.Request
	)

	types.NewTryIO(func() (string, error) {
		return util.ParseJSONBody(ctx, &requestData)
	}).
		ThenString(func(_ string) (string, error) {
			return user.ValidateUsername(ctx, requestData, &username)
		}).
		ThenString(func(_ string) (string, error) {
			sessionKey := "webauthn_login_session:" + username
			return session.GetWebauthnSessionData(
				ctx, redisClient, sessionKey,
			)
		}).
		ThenBytes(func(redisSessionData string) ([]byte, error) {
			// Get session data from Redis
			return util.UnmarshalAndRespondOnError(ctx, []byte(redisSessionData), &sessionData)
		}).
		ThenBytes(func(_ []byte) ([]byte, error) {
			// Marshal credential field
			return util.MarshalAndRespondOnError(ctx, requestData["credential"])
		}).
		ThenHttpRequest(func(credentialData []byte) (*http.Request, error) {
			// TODO: will refactor this later
			ctx.Request.SetBody(credentialData)
			return util.ConvertFastHTTPToHTTPRequest(ctx, &convertedRequest)
		}).
		ThenString(func(req *http.Request) (string, error) {
			return user.QueryUserWebauthnByUsername(
				db, username,
				&userID, &webauthnUserID, &displayName,
				&credentialIDEncoded, &credentialPublicKeyEncoded,
			)
		}).
		ThenBytes(func(_ string) ([]byte, error) {
			return util.DecodeCredentialID(ctx, credentialIDEncoded)
		}).
		ThenBytes(func(credID []byte) ([]byte, error) {
			credentialID = credID
			return util.DecodeCredentialPublicKey(ctx, credentialPublicKeyEncoded, &credentialPublicKey)
		}).
		ThenWebAuthnUser(func(_ []byte) (*types.WebAuthnUser, error) {
			return util.NewWebAuthnUserWithBackupEligible(
				webauthnUserID, username, displayName,
				credentialID, credentialPublicKey,
				true,
			)
		}).
		ThenWebAuthnCredential(func(webauthnuser *types.WebAuthnUser) (*webauthn.Credential, error) {
			WebAuthnUser = *webauthnuser
			return util.FinishLogin(ctx, webauthnuser, sessionData, &convertedRequest)
		}).
		ThenSQLResult(func(webauthnCredential *webauthn.Credential) (sql.Result, error) {
			// 0 is a placeholder, replace with actual sign count if needed
			return user.UpdateUserWebauthnSignCount(
				db, 0, username,
			)
		}).
		ThenBytes(func(_ sql.Result) ([]byte, error) {
			responseData := map[string]interface{}{
				"message": "Login verification successful",
				"user":    WebAuthnUser,
			}
			return util.MarshalAndRespondOnError(ctx, responseData)
		}).
		Match(
			func(err error) {
				if appErr, ok := err.(*weberror.AppError); ok {
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
				} else {
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					ctx.SetContentType("application/json")
					ctx.SetBodyString(`{"error": "Internal server error"}`)
					zap.L().Error(
						"Unexpected error in HandleAuthenticateVerification",
						zap.Error(err),
					)
				}
			},
			func(responseJSON []byte) {
				ctx.SetContentType("application/json")
				ctx.SetStatusCode(fasthttp.StatusOK)
				ctx.SetBody(responseJSON)
			},
		)
}
