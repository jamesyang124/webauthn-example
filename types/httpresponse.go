// Package types defines shared types and response helpers for the WebAuthn example application.
package types

import (
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type HTTPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RespondWithError writes an error response and logs the error using zap
func RespondWithError(ctx *fasthttp.RequestCtx, status int, message string, logMessage string, logArgs ...interface{}) {
	ctx.SetStatusCode(status)
	ctx.SetBodyString(message)
	if logMessage != "" {
		zap.L().Error(logMessage, zap.Any("args", logArgs))
	}
}
