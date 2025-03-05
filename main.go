package main

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-go/examples" // Import without alias
	"github.com/valyala/fasthttp"
)

var webAuthn *webauthn.WebAuthn

func main() {
	// Initialize WebAuthn
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "jamesyang124 WebAuthn Example Apps", // Display Name for your site
		RPID:          "localhost",                          // Generally the domain name for your site
		RPOrigins:     []string{"http://localhost:8080"},    // The origin URL for WebAuthn requests
	})
	if err != nil {
		fmt.Printf("Failed to create WebAuthn from config: %s", err)
		return
	}

	// Define request handler
	requestHandler := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			fmt.Fprintf(ctx, "Welcome to the high-performance API server!")
		case "/register":
			examples.HandleRegister(ctx) // Updated function call
		case "/authenticate":
			examples.HandleAuthenticate(ctx) // Updated function call
		default:
			ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		}
	}

	// Start the server
	if err := fasthttp.ListenAndServe(":8080", requestHandler); err != nil {
		fmt.Printf("Error in ListenAndServe: %s", err)
	}
}
