package main

import (
	"fmt"
	"log"

	"github.com/fasthttp/router"
	"github.com/jamesyang124/webauthn-go/examples"
	"github.com/jamesyang124/webauthn-go/types"
	"github.com/valyala/fasthttp"
)

func authRegister() func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		fmt.Fprintf(ctx, "Welcome to the email/username basic auth registration!")
	}
}

func rootPage(ctx *fasthttp.RequestCtx) {
	ctx.SendFile("static/index.html")
}

func authLogin(persistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthLogin(persistance.Db, logger)(ctx)
	}
}

func waOptions(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		username := string(ctx.FormValue("username"))
		if username == "" {
			username = "user1"
		}
		ctx.QueryArgs().Add("username", username)
		examples.HandleWebAuthnOptions(presistance.Db, logger, presistance.Cache)(ctx)
	}
}

func waVerification(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		// Parse JSON input
		examples.HandleVerification(ctx, presistance.Db, logger, presistance.Cache)
	}
}

func waAuthenticate(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
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

		examples.HandleAuthenticate(ctx, presistance.Db, logger)
	}
}

func PrepareRoutes(persistance *types.Persistance, logger *log.Logger) *router.Router {

	routes := router.New()

	routes.GET("/*", rootPage)
	routes.GET("/auth/login", authLogin(persistance, logger))
	routes.GET("/auth/register", authRegister())

	waRegister := routes.Group("/webauthn/register")
	waRegister.GET("/options", waOptions(persistance, logger))
	waRegister.POST("/verification", waVerification(persistance, logger))

	waAuth := routes.Group("/webauthn/authenticate")
	waAuth.GET("/", waAuthenticate(persistance, logger))

	return routes
}
