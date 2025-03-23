package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/fasthttp/router"
	"github.com/jamesyang124/webauthn-go/examples"
	"github.com/jamesyang124/webauthn-go/middlewares"
	"github.com/jamesyang124/webauthn-go/types"
	"github.com/valyala/fasthttp"
)

func authRegister() func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		fmt.Fprintf(ctx, "Welcome to the email/username basic auth registration!")
	}
}

func rootPage(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json; charset=utf-8")
	timestamp := fmt.Sprintf("Version: %s", ctx.Time().Format("2006-01-02 15:04:05"))
	response := map[string]string{
		"message": "Welcome to WebAuthn Example",
		"version": timestamp,
	}
	jsonResponse, _ := json.Marshal(response)
	ctx.SetBody(jsonResponse)
}

func authLogin(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthLogin(ctx, persistance.Db)
	}
}

func waRegisterOptions(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleRegisterOptions(ctx, persistance.Db, persistance.Cache)
	}
}

func waRegisterVerification(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		// Parse JSON input
		examples.HandleRegisterVerification(ctx, persistance.Db, persistance.Cache)
	}
}

func waAuthenticateOptions(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthenticateOptions(ctx, persistance.Db, persistance.Cache)
	}
}

func waAuthenticateVerification(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		examples.HandleAuthenticateVerification(ctx, persistance.Db, persistance.Cache)
	}
}

func notFoundHandler(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusNotFound)
	ctx.SetContentType("application/json; charset=utf-8")
	response := map[string]string{
		"error":   "Not Found",
		"message": "The requested resource could not be found.",
	}
	jsonResponse, _ := json.Marshal(response)
	ctx.SetBody(jsonResponse)
}

func PrepareRoutes(logger *log.Logger, persistance *types.Persistance) fasthttp.RequestHandler {

	routes := router.New()

	routes.GET("/version", rootPage)
	routes.POST("/auth/login", authLogin(persistance))
	routes.POST("/auth/register", authRegister())

	waRegister := routes.Group("/webauthn/register")
	waRegister.POST("/options", waRegisterOptions(persistance))
	waRegister.POST("/verification", waRegisterVerification(persistance))

	waAuth := routes.Group("/webauthn/authenticate")
	waAuth.POST("/options", waAuthenticateOptions(persistance))
	waAuth.POST("/verification", waAuthenticateVerification(persistance))

	routes.NotFound = notFoundHandler

	return middlewares.CorsMiddleware(routes.Handler)
}
