package userrepo

import (
	"fmt"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// ValidateUsernameAndDisplayname validates and extracts username and displayname from requestData.
func ValidateUsernameAndDisplayname(ctx *fasthttp.RequestCtx, requestData map[string]interface{}) (string, string, error) {
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		zap.L().Error("Invalid username type")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid username type"}`)
		return "", "", fmt.Errorf("invalid or missing username")
	}
	displayname, ok := requestData["displayname"].(string)
	if !ok || displayname == "" {
		zap.L().Error("Invalid displayname type")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid displayname type"}`)
		return "", "", fmt.Errorf("invalid or missing displayname")
	}
	return username, displayname, nil
}
