package examples

import (
	"database/sql"
	"encoding/json"
	"log"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

func HandleRegister(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger) {
	// Implement WebAuthn registration logic using go-webauthn
	// ...
	logger.Println("HandleRegister called")
}

func HandleAuthenticate(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger) {
	useremail := string(ctx.FormValue("email"))
	inputPassword := string(ctx.FormValue("password"))

	var username, webauthnID, createDate string
	var userID int

	err := db.QueryRow("SELECT id, username, COALESCE(webauthn_id, ''), created_at FROM users WHERE email=$1 AND password_hash=crypt($2, password_hash)", useremail, inputPassword).Scan(&userID, &username, &webauthnID, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.Error("User not found or invalid password", fasthttp.StatusUnauthorized)
		} else {
			ctx.Error("Database query error", fasthttp.StatusInternalServerError)
		}
		logger.Printf("Error in HandleAuthenticate: %s", err)
		return
	}

	response := map[string]interface{}{
		"username":    username,
		"id":          userID,
		"webauthn_id": webauthnID,
		"create_date": createDate,
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
		logger.Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(string(responseJSON))

	// Implement WebAuthn authentication logic using go-webauthn
	// ...
	logger.Println("HandleAuthenticate called")
}
