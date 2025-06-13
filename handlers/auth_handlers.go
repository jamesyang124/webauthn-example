package handlers

import (
	"database/sql"
	"encoding/json"

	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
)

func HandleAuthLogin(ctx *fasthttp.RequestCtx, db *sql.DB) {

	useremail := string(ctx.FormValue("email"))
	inputPassword := string(ctx.FormValue("password"))

	var username, createDate string
	var userID int

	err := db.QueryRow("SELECT id, username, created_at FROM users WHERE email=$1 AND password_hash=crypt($2, password_hash)", useremail, inputPassword).Scan(&userID, &username, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			types.RespondWithError(ctx, fasthttp.StatusUnauthorized, "User not found or invalid password", "User not found or invalid password", err)
		} else {
			types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Database query error", "Database query error", err)
		}
		return
	}

	response := map[string]interface{}{
		"username":    username,
		"id":          userID,
		"create_date": createDate,
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusInternalServerError, "Failed to marshal response", "Error marshaling response", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(string(responseJSON))
}
