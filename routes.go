package main

import (
	"encoding/json"
	"fmt"

	"github.com/fasthttp/router"
	"github.com/jamesyang124/webauthn-example/handlers"
	"github.com/jamesyang124/webauthn-example/middlewares"
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
)

func rootPage(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/html")
	ctx.SendFile("./views/dist/index.html")
}

func versionHandler(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json; charset=utf-8")
	timestamp := fmt.Sprintf("Version: %s", ctx.Time().Format("2006-01-02 15:04:05"))
	response := map[string]string{
		"message": "Welcome to WebAuthn Example",
		"version": timestamp,
	}
	jsonResponse, _ := json.Marshal(response)
	ctx.SetBody(jsonResponse)
}

func waRegisterOptions(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		handlers.HandleRegisterOptions(ctx, persistance.Db, persistance.Cache)
	}
}

func waRegisterVerification(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		// Parse JSON input
		handlers.HandleRegisterVerification(ctx, persistance.Db, persistance.Cache)
	}
}

func waAuthenticateOptions(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		handlers.HandleAuthenticateOptions(ctx, persistance.Db, persistance.Cache)
	}
}

func waAuthenticateVerification(persistance *types.Persistance) func(ctx *fasthttp.RequestCtx) {
	return func(ctx *fasthttp.RequestCtx) {
		handlers.HandleAuthenticateVerification(ctx, persistance.Db, persistance.Cache)
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

func PrepareRoutes(persistance *types.Persistance) fasthttp.RequestHandler {
	routes := router.New()

	routes.GET("/", rootPage)
	routes.ServeFiles("/{filepath:*}", "./views/dist")
	routes.ServeFiles("/assets/{filepath:*}", "./views/dist/assets")

	routes.GET("/version", versionHandler)

	waRegister := routes.Group("/webauthn/register")
	waRegister.POST("/options", waRegisterOptions(persistance))
	waRegister.POST("/verification", waRegisterVerification(persistance))

	waAuth := routes.Group("/webauthn/authenticate")
	waAuth.POST("/options", waAuthenticateOptions(persistance))
	waAuth.POST("/verification", waAuthenticateVerification(persistance))

	routes.NotFound = notFoundHandler

	return middlewares.CorsMiddleware(routes.Handler)
}
