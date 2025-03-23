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
	ctx.SendFile("./static/index.html")
}

func authLogin(persistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthLogin(persistance.Db, logger)(ctx)
	}
}

func waRegisterOptions(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleRegisterOptions(presistance.Db, logger, presistance.Cache)(ctx)
	}
}

func waRegisterVerification(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		// Parse JSON input
		examples.HandleRegisterVerification(ctx, presistance.Db, logger, presistance.Cache)
	}
}

func waAuthenticateOptions(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthenticateOptions(ctx, presistance.Db, logger, presistance.Cache)
	}
}

func waAuthenticateVerification(presistance *types.Persistance, logger *log.Logger) func(ctx *fasthttp.RequestCtx) {
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

		examples.HandleAuthenticateVerification(ctx, presistance.Db, logger)
	}
}

func PrepareRoutes(persistance *types.Persistance, logger *log.Logger) *router.Router {

	routes := router.New()

	routes.GET("/", rootPage)
	routes.GET("/auth/login", authLogin(persistance, logger))
	routes.GET("/auth/register", authRegister())

	routes.ServeFiles("/assets/{filepath:*}", "./static")

	waRegister := routes.Group("/webauthn/register")
	waRegister.POST("/options", waRegisterOptions(persistance, logger))
	waRegister.POST("/verification", waRegisterVerification(persistance, logger))

	waAuth := routes.Group("/webauthn/authenticate")
	waAuth.POST("/options", waAuthenticateOptions(persistance, logger))
	waAuth.POST("/verification", waAuthenticateVerification(persistance, logger))

	return routes
}
