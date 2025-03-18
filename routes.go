package main

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/fasthttp/router"
	"github.com/jamesyang124/webauthn-go/examples"
	"github.com/valyala/fasthttp"
)

func authRegister(db *sql.DB, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		fmt.Fprintf(ctx, "Welcome to the email/username basic auth registration!")
	}
}

func rootPage(ctx *fasthttp.RequestCtx) {
	ctx.SendFile("static/index.html")
}

func authLogin(db *sql.DB, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthLogin(db, logger)(ctx)
	}
}

func webAuthnOptions(db *sql.DB, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		username := string(ctx.FormValue("username"))
		if username == "" {
			username = "user1"
		}
		ctx.QueryArgs().Add("username", username)
		examples.HandleWebAuthnOptions(db, logger)(ctx)
	}
}

func webAuthnVerification(db *sql.DB, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("text/html")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(string(ctx.Path()))
	}
}

func webAuthnAuthenticate(db *sql.DB, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
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

		examples.HandleAuthenticate(ctx, db, logger)
	}
}

func PrepareRoutes(db *sql.DB, logger *log.Logger) *router.Router {

	routes := router.New()

	routes.GET("/*", rootPage)
	routes.GET("/auth/login", authLogin(db, logger))
	routes.GET("/auth/register", authRegister(db, logger))

	waRegister := routes.Group("/webauthn/register")
	waRegister.GET("/options", webAuthnOptions(db, logger))
	waRegister.POST("/verification", webAuthnVerification(db, logger))

	waAuth := routes.Group("/webauthn/authenticate")
	waAuth.GET("/", webAuthnAuthenticate(db, logger))

	return routes
}
