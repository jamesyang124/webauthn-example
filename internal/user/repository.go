package userrepo

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

// UpdateUserWebauthnCredentials updates the user's webauthn credentials and handles error responses.
func UpdateUserWebauthnCredentials(ctx *fasthttp.RequestCtx, db *sql.DB, userID string, signCount uint32, credentialIdEncoded, credentialPublicKeyEncoded, displayName, username string) (sql.Result, error) {
	query := `UPDATE users SET webauthn_user_id = $1, webauthn_sign_count = $2, webauthn_credential_id = $3, webauthn_credential_public_key = $4, webauthn_displayname = $5 WHERE username = $6`
	result, err := db.Exec(query, userID, signCount, credentialIdEncoded, credentialPublicKeyEncoded, displayName, username)
	if err != nil {
		zap.L().Error("Error updating user webauthn credentials", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist credential data"}`)
		return nil, err
	}
	return result, nil
}

// UpdateUserWebauthnSignCount updates the user's webauthn sign count and handles error responses.
func UpdateUserWebauthnSignCount(ctx *fasthttp.RequestCtx, db *sql.DB, signCount uint32, username string) (sql.Result, error) {
	query := `UPDATE users SET webauthn_sign_count = $1 WHERE username = $2`
	result, err := db.Exec(query, signCount, username)
	if err != nil {
		zap.L().Error("Error updating user webauthn sign count", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to update sign count"}`)
		return nil, err
	}
	return result, nil
}
