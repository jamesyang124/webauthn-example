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
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	session "github.com/jamesyang124/webauthn-example/internal/session"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/jamesyang124/webauthn-example/types"
	fasthttp "github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// HandleRegisterOptions handles the WebAuthn registration options using TryIO monad chains
func HandleRegisterOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Shared variables for the chain
	var (
		requestData    map[string]interface{}
		username       string
		webauthnUserID uuid.UUID
		options        *protocol.CredentialCreation
		sessionData    *webauthn.SessionData
	)

	// Parse request JSON body into map
	types.NewTryIO(func() (string, error) {
		return util.ParseJSONBody(ctx, &requestData)
	}).
		// Validate username from request data
		ThenString(func(_ string) (string, error) {
			return user.ValidateUsername(ctx, requestData, &username)
		}).
		// Query user by username from database
		ThenString(func(validatedUsername string) (string, error) {
			var userID, createDate string
			return user.QueryUserByUsername(db, username, &userID, &username, &createDate)
		}).
		// Generate new UUID for WebAuthn user ID
		ThenUUID(func(_ string) (uuid.UUID, error) {
			return uuid.NewV7()
		}).
		// Create new WebAuthn user struct
		ThenWebAuthnUser(func(uuidVal uuid.UUID) (*types.WebAuthnUser, error) {
			webauthnUserID = uuidVal
			return util.NewWebAuthnUser(
				webauthnUserID.String(),
				username,
				username,
			), nil
		}).
		// Begin WebAuthn registration process
		ThenCredentialCreation(func(webAuthnUser *types.WebAuthnUser) (*protocol.CredentialCreation, error) {
			opts, sessData, ok := util.BeginRegistration(ctx, webAuthnUser)
			if !ok {
				return nil, weberror.WebAuthnBeginRegistrationError(nil)
			}
			options = opts
			sessionData = sessData
			return options, nil
		}).
		// Marshal session data to JSON
		ThenBytes(func(_ *protocol.CredentialCreation) ([]byte, error) {
			return util.MarshalAndRespondOnError(ctx, sessionData)
		}).
		// Store session data in Redis with TTL
		ThenBytes(func(sessionDataJSON []byte) ([]byte, error) {
			sessionKey := "webauthn_session:" + username
			return session.SetWebauthnSessionData(ctx, redisClient, sessionKey, sessionDataJSON, 86400*time.Second)
		}).
		// Marshal registration options for response
		ThenBytes(func(_ []byte) ([]byte, error) {
			return util.MarshalAndRespondOnError(ctx, options)
		}).
		Match(
			func(err error) {
				// Handle error through weberror system
				if appErr, ok := err.(*weberror.AppError); ok {
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
				} else {
					appErr := weberror.UnexpectedError(err, "HandleRegisterOptions")
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
				}
			},
			func(responseJSON []byte) {
				// Send success response
				ctx.SetContentType("application/json")
				ctx.SetStatusCode(fasthttp.StatusOK)
				ctx.SetBody(responseJSON)
				zap.L().Info("HandleRegisterOptions completed successfully")
			},
		)
}

// HandleRegisterVerification handles the verification of WebAuthn registration using TryIO monad chains
func HandleRegisterVerification(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	// Shared variables for the chain
	var (
		requestData       map[string]interface{}
		username          string
		sessionData       webauthn.SessionData
		convertedRequest  http.Request
		webAuthnUser      *types.WebAuthnUser
		credential        *webauthn.Credential
	)

	// Parse request JSON body into map
	types.NewTryIO(func() (string, error) {
		return util.ParseJSONBody(ctx, &requestData)
	}).
		// Validate username and display name from request
		ThenString(func(_ string) (string, error) {
			validatedUsername, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
			if err != nil {
				return "", err
			}
			username = validatedUsername
			return username, nil
		}).
		// Retrieve session data from Redis
		ThenString(func(_ string) (string, error) {
			sessionKey := "webauthn_session:" + username
			return session.GetWebauthnSessionData(ctx, redisClient, sessionKey)
		}).
		// Unmarshal session data from JSON
		ThenBytes(func(redisSessionData string) ([]byte, error) {
			zap.L().Info("Register verify sessionDataStr", zap.String("sessionDataStr", redisSessionData))
			return util.UnmarshalAndRespondOnError(ctx, []byte(redisSessionData), &sessionData)
		}).
		// Marshal credential data from request
		ThenBytes(func(_ []byte) ([]byte, error) {
			return util.MarshalAndRespondOnError(ctx, requestData["credential"])
		}).
		// Convert FastHTTP request to standard HTTP request
		ThenHttpRequest(func(credentialData []byte) (*http.Request, error) {
			ctx.Request.SetBody(credentialData)
			zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))
			return util.ConvertFastHTTPToHTTPRequest(ctx, &convertedRequest)
		}).
		// Query user by username from database
		ThenString(func(req *http.Request) (string, error) {
			var userID, createDate string
			return user.QueryUserByUsername(db, username, &userID, &username, &createDate)
		}).
		// Create WebAuthn user with session data
		ThenWebAuthnUser(func(validatedUsername string) (*types.WebAuthnUser, error) {
			webAuthnUser = util.NewWebAuthnUser(
				string(sessionData.UserID),
				username,
				username,
			)
			return webAuthnUser, nil
		}).
		// Finish WebAuthn registration process
		ThenWebAuthnCredential(func(user *types.WebAuthnUser) (*webauthn.Credential, error) {
			cred, ok := util.FinishRegistration(ctx, user, sessionData, &convertedRequest)
			if !ok {
				return nil, weberror.WebAuthnFinishRegistrationError(nil)
			}
			credential = cred
			return credential, nil
		}).
		// Update user with WebAuthn credentials in database
		ThenSQLResult(func(cred *webauthn.Credential) (sql.Result, error) {
			// Encode credential public key and ID for storage
			credentialPublicKeyEncoded := util.EncodeRawURLEncoding(cred.PublicKey)
			credentialIDEncoded := util.EncodeRawURLEncoding(cred.ID)
			
			zap.L().Info("credentialPublicKeyEncoded", zap.String("credentialPublicKeyEncoded", credentialPublicKeyEncoded))
			zap.L().Info("credentialIDEncoded", zap.String("credentialIDEncoded", credentialIDEncoded))
			
			return user.UpdateUserWebauthnCredentials(db,
				webAuthnUser.ID,
				cred.Authenticator.SignCount,
				credentialIDEncoded,
				credentialPublicKeyEncoded,
				username,
				username,
			)
		}).
		// Check rows affected and marshal final response
		ThenBytes(func(result sql.Result) ([]byte, error) {
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return nil, weberror.DatabaseQueryError(err, "get rows affected")
			}
			zap.L().Info("rows affected", zap.Int64("rowsAffected", rowsAffected))
			
			responseData := map[string]interface{}{
				"credential": credential,
				"payload":    requestData,
				"message":    "Verification successful",
				"path":       string(ctx.Path()),
			}
			return util.MarshalAndRespondOnError(ctx, responseData)
		}).
		Match(
			func(err error) {
				// Handle error through weberror system
				if appErr, ok := err.(*weberror.AppError); ok {
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
				} else {
					appErr := weberror.UnexpectedError(err, "HandleRegisterVerification")
					httpErr := weberror.ToHTTPError(appErr)
					httpErr.RespondAndLog(ctx)
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
