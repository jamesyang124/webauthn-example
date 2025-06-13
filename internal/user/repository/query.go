package repository

import (
	"database/sql"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// ExecAndRespondOnError executes a DB statement and handles error response if execution fails.
func ExecAndRespondOnError(ctx *fasthttp.RequestCtx, db *sql.DB, query string, args ...interface{}) (sql.Result, error) {
	result, err := db.Exec(query, args...)
	if err != nil {
		zap.L().Error("Error executing DB statement", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		return nil, err
	}
	return result, nil
}

// QueryUserByUsername queries the user by username and handles error responses.
func QueryUserByUsername(ctx *fasthttp.RequestCtx, dbConn *sql.DB, username string, userID, usernameOut, createDate *string) error {
	err := dbConn.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).Scan(userID, usernameOut, createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString(`{"error": "WebAuthnUser not found or invalid password"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		zap.L().Error("Error querying user", zap.Error(err))
		return err
	}
	return nil
}

// QueryUserWebauthnByUsername queries the user and webauthn fields by username and handles error responses.
func QueryUserWebauthnByUsername(ctx *fasthttp.RequestCtx, dbConn *sql.DB, username string, userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded *string) error {
	err := dbConn.QueryRow("SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1", username).Scan(userID, webauthnUserID, displayName, credentialIdEncoded, credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString(`{"error": "User not found"}`)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Database query error"}`)
		}
		zap.L().Error("Error querying user", zap.Error(err))
		return err
	}
	return nil
}
