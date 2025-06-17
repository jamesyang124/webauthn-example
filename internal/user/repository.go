// Package user provides user-related database operations and validation logic for WebAuthn flows.
package user

import (
	"database/sql"

	"github.com/jamesyang124/webauthn-example/internal/weberror"
)

// ExecAndRespondOnError executes a DB statement and returns error for handler-level handling.
func ExecAndRespondOnError(
	db *sql.DB,
	query string,
	args ...interface{},
) (sql.Result, error) {
	result, err := db.Exec(query, args...)
	if err != nil {
		return nil, weberror.DatabaseQueryError(err, "execute DB statement")
	}
	return result, nil
}

// QueryUserByUsername queries the user by username and returns error for handler-level handling.
func QueryUserByUsername(
	dbConn *sql.DB,
	username string,
	userID, usernameOut, createDate *string,
) error {
	err := dbConn.QueryRow("SELECT id, username, created_at FROM users WHERE username=$1", username).
		Scan(userID, usernameOut, createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return weberror.UserNotFoundError(err, "query user by username")
		}
		return weberror.DatabaseQueryError(err, "query user by username")
	}
	return nil
}

// QueryUserWebauthnByUsername queries the user and webauthn fields by username using TryIO pattern.
func QueryUserWebauthnByUsername(
	dbConn *sql.DB,
	username string,
	userID, webauthnUserID, displayName, credentialIDEncoded, credentialPublicKeyEncoded *string,
) (string, error) {
	err := dbConn.QueryRow(
		"SELECT id, webauthn_user_id, webauthn_displayname, webauthn_credential_id, webauthn_credential_public_key FROM users WHERE username=$1",
		username,
	).Scan(userID, webauthnUserID, displayName, credentialIDEncoded, credentialPublicKeyEncoded)
	if err != nil {
		if err == sql.ErrNoRows {
			return *userID, weberror.UserNotFoundError(err, "query user by username")
		}
		return *userID, weberror.DatabaseQueryError(err, "query user by username")
	}
	return *userID, nil
}

// UpdateUserWebauthnCredentials updates the user's webauthn credentials and returns error for handler-level handling.
func UpdateUserWebauthnCredentials(
	db *sql.DB,
	userID string,
	signCount uint32,
	credentialIDEncoded, credentialPublicKeyEncoded, displayName, username string,
) (sql.Result, error) {
	query := `UPDATE users SET webauthn_user_id = $1, webauthn_sign_count = $2, webauthn_credential_id = $3, webauthn_credential_public_key = $4, webauthn_displayname = $5 WHERE username = $6`
	result, err := db.Exec(
		query,
		userID,
		signCount,
		credentialIDEncoded,
		credentialPublicKeyEncoded,
		displayName,
		username,
	)
	if err != nil {
		return nil, weberror.DatabaseUpdateError(err, "update user webauthn credentials")
	}
	return result, nil
}

// UpdateUserWebauthnSignCount updates the user's webauthn sign count and returns error for handler-level handling.
func UpdateUserWebauthnSignCount(db *sql.DB, signCount uint32, username string) (sql.Result, error) {
	query := `UPDATE users SET webauthn_sign_count = $1 WHERE username = $2`
	result, err := db.Exec(query, signCount, username)
	if err != nil {
		return nil, weberror.DatabaseUpdateError(err, "update user webauthn sign count")
	}
	return result, nil
}
