package examples

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-go/types" // Import the types package
	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

var (
	webAuthn     *webauthn.WebAuthn
	registerTmpl *template.Template
)

func init() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Example Corp",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		log.Fatalf("failed to create WebAuthn instance: %v", err)
	}

	registerTmpl, err = template.ParseFiles("templates/register.html.tmpl")
	if err != nil {
		log.Fatalf("failed to parse HTML template: %v", err)
	}
}

func HandleRegister(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger) {
	username := string(ctx.FormValue("username"))

	var userID, webauthnID, createDate string

	err := db.QueryRow("SELECT id, username, COALESCE(webauthn_id, ''), created_at FROM users WHERE username=$1", username).Scan(&userID, &username, &webauthnID, &createDate)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.Error("WebAuthnUser not found or invalid password", fasthttp.StatusUnauthorized)
		} else {
			ctx.Error("Database query error", fasthttp.StatusInternalServerError)
		}
		logger.Printf("Error in HandleAuthenticate: %s", err)
		return
	}

	WebAuthnUser := &types.WebAuthnUser{ // Use the imported WebAuthnUser type
		ID:          webauthnID,
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	// TODO: _ is sessionData shold persist in later block
	options, _, err := webAuthn.BeginRegistration(WebAuthnUser)
	if err != nil {
		ctx.Error("Failed to begin WebAuthn registration", fasthttp.StatusInternalServerError)
		logger.Printf("Error beginning WebAuthn registration: %s", err)
		return
	}

	// Store sessionData in your session store (not shown here)
	// ...

	responseJSON, err := json.Marshal(options)
	if err != nil {
		ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
		logger.Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("text/html")
	ctx.SetStatusCode(fasthttp.StatusOK)

	err = registerTmpl.Execute(ctx.Response.BodyWriter(), map[string]string{
		"options": string(responseJSON),
	})
	if err != nil {
		ctx.Error("Failed to execute HTML template", fasthttp.StatusInternalServerError)
		logger.Printf("Error executing HTML template: %s", err)
		return
	}

	logger.Println("HandleRegister called")
}

func HandleAuthenticate(ctx *fasthttp.RequestCtx, db *sql.DB, logger *log.Logger) {
	//username := string(ctx.FormValue("username"))

	responseJSON, err := json.Marshal("")
	if err != nil {
		ctx.Error("Failed to marshal response", fasthttp.StatusInternalServerError)
		logger.Printf("Error marshaling response: %s", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(string(responseJSON))

	logger.Println("HandleAuthenticate called")
}
