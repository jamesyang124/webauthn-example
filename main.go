package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-go/examples" // Import without alias
	"github.com/joho/godotenv"                     // Import godotenv package
	_ "github.com/lib/pq"                          // Import PostgreSQL driver
	"github.com/valyala/fasthttp"
)

var (
	webAuthn *webauthn.WebAuthn
	db       *sql.DB
	logger   *log.Logger
)

func main() {
	// Initialize logger
	logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		logger.Printf("Error loading .env file: %s", err)
		return
	}

	// Initialize WebAuthn
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "jamesyang124 WebAuthn Example Apps", // Display Name for your site
		RPID:          "localhost",                          // Generally the domain name for your site
		RPOrigins:     []string{"http://localhost:8080"},    // The origin URL for WebAuthn requests
	})
	if err != nil {
		logger.Printf("Failed to create WebAuthn from config: %s", err)
		return
	}

	// Initialize database connection
	connStr := os.Getenv("DATABASE_URL")
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		logger.Printf("Failed to connect to database: %s", err)
		return
	}
	defer db.Close()

	// Define request handler
	requestHandler := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			fmt.Fprintf(ctx, "Welcome to the high-performance API server!")
		case "/auth/login":
			fmt.Fprintf(ctx, "Welcome to the email/username basic auth login!")
		case "/auth/register":
			fmt.Fprintf(ctx, "Welcome to the email/username basic auth registration!")
		case "/webauthn/register":
			username := string(ctx.FormValue("username"))
			if username == "" {
				username = "user1"
			}
			ctx.QueryArgs().Add("username", username)

			examples.HandleRegister(ctx, db, logger) // Updated function call
		case "/webauthn/authenticate":
			// Supply default POST arguments or query arguments
			email := string(ctx.FormValue("email"))
			password := string(ctx.FormValue("password"))
			if email == "" {
				email = "user1@example.com"
			}
			if password == "" {
				password = "password1"
			}
			ctx.QueryArgs().Add("email", email)
			ctx.QueryArgs().Add("password", password)

			examples.HandleAuthenticate(ctx, db, logger) // Updated function call
		default:
			ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		}
	}

	// Start the server
	logger.Println("Starting server on :8080")
	if err := fasthttp.ListenAndServe(":8080", requestHandler); err != nil {
		logger.Printf("Error in ListenAndServe: %s", err)
	}
}
