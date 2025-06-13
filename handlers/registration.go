// Package handlers provides HTTP handlers for WebAuthn registration and authentication flows.
//
// This package contains the implementation of the HTTP handlers that manage the
// WebAuthn registration and authentication processes. It includes handling
// registration options, verification of registration, authentication options,
// and verification of authentication. The handlers interact with the database
// and Redis for session management and user credential storage. They also
// handle the parsing and marshaling of JSON data, as well as the conversion
// of requests between fasthttp and net/http formats.
//
// The package is designed to be used as part of a web application that
// implements WebAuthn for user authentication. It relies on other packages
// for the underlying WebAuthn protocol implementation and database access.
//
// Example usage:
//
//	package main
//
//	import (
//	    "database/sql"
//	    "github.com/go-redis/redis/v8"
//	    "github.com/jamesyang124/webauthn-example/handlers"
//	    "github.com/valyala/fasthttp"
//	)
//
//	func main() {
//	    db := // initialize your database connection
//	    redisClient := // initialize your Redis client
//
//	    fasthttp.ListenAndServe(":8080", func(ctx *fasthttp.RequestCtx) {
//	        switch string(ctx.Path()) {
//	        case "/register/options":
//	            handlers.HandleRegisterOptions(ctx, db, redisClient)
//	        case "/register/verify":
//	            handlers.HandleRegisterVerification(ctx, db, redisClient)
//	        // add other routes for authentication and other handlers
//	        default:
//	            ctx.SetStatusCode(fasthttp.StatusNotFound)
//	        }
//	    })
//	}
package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	session "github.com/jamesyang124/webauthn-example/internal/session"
	user "github.com/jamesyang124/webauthn-example/internal/user"
	util "github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/types"
	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"
)

// HandleRegisterOptions handles the WebAuthn registration options
func HandleRegisterOptions(ctx *fasthttp.RequestCtx, db *sql.DB, redisClient *redis.Client) {
	var requestData map[string]interface{}
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	username, ok := user.ExtractUsername(ctx, requestData)
	if !ok {
		return
	}

	var userID, createDate string
	err := user.QueryUserByUsername(ctx, db, username, &userID, &username, &createDate)
	if err != nil {
		return
	}

	webauthnUserID, err := uuid.NewV7()
	if err != nil {
		zErr := zap.L().Error
		zErr("Error to generate webauthn user id uuidv7", zap.Error(err))
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError,
			"Error to generate webauthn user id uuidv7",
			"Error to generate webauthn user id uuidv7", err)
	}

	WebAuthnUser := util.NewWebAuthnUser(
		webauthnUserID.String(),
		username,
		username,
	)

	options, sessionData, ok := util.BeginRegistration(ctx, WebAuthnUser)
	if !ok {
		return
	}

	sessionKey := "webauthn_session:" + username
	sessionDataJson, err := util.MarshalAndRespondOnError(ctx, sessionData)
	if err != nil {
		return
	}
	if !session.SetWebauthnSessionDataWithErrorHandling(
		ctx,
		redisClient,
		sessionKey,
		sessionDataJson,
		86400*time.Second,
	) {
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
	var requestData map[string]interface{}
	if err := util.ParseJSONBody(ctx, &requestData); err != nil {
		return
	}

	username, _, err := user.ValidateUsernameAndDisplayname(ctx, requestData)
	if err != nil {
		return
	}

	sessionKey := "webauthn_session:" + username
	var sessionData webauthn.SessionData
	redisSessionData, ok := session.GetWebauthnSessionDataWithErrorHandling(
		ctx,
		redisClient,
		sessionKey,
	)
	if !ok {
		return
	}
	if !util.UnmarshalAndRespondOnError(ctx, []byte(redisSessionData), &sessionData) {
		return
	}

	zap.L().Info("Register verify sessionDataStr", zap.String("sessionDataStr", redisSessionData))

	credentialData, err := util.MarshalAndRespondOnError(ctx, requestData["credential"])
	if err != nil {
		return
	}

	var credentialMap map[string]interface{}
	if err := util.ParseJSONBody(ctx, &credentialMap); err != nil {
		zErr := zap.L().Error
		zErr("Error unmarshaling credential data", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid credential data"}`)
		return
	}

	ctx.Request.SetBody(credentialData)
	zap.L().Info("Overridden PostBody", zap.String("postBody", string(ctx.PostBody())))

	var httpRequest http.Request
	err = fasthttpadaptor.ConvertRequest(ctx, &httpRequest, true)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to convert request"}`)
		zap.L().Error("Error converting fasthttp request", zap.Error(err))
		return
	}

	var userID, createDate string
	err = user.QueryUserByUsername(ctx, db, username, &userID, &username, &createDate)
	if err != nil {
		return
	}

	WebAuthnUser := util.NewWebAuthnUser(
		string(sessionData.UserID),
		username,
		username,
	)

	credential, ok := util.FinishRegistration(ctx, WebAuthnUser, sessionData, &httpRequest)
	if !ok {
		return
	}

	credentialPublicKeyEncoded := util.EncodeRawURLEncoding(credential.PublicKey)
	zap.L().
		Info("credentialPublicKeyEncoded", zap.String("credentialPublicKeyEncoded", credentialPublicKeyEncoded))

	credentialIdEncoded := util.EncodeRawURLEncoding(credential.ID)
	zap.L().Info("credentialIdEncoded", zap.String("credentialIdEncoded", credentialIdEncoded))

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
