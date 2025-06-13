// Package user provides user-related database operations and validation logic for WebAuthn flows.
// It includes functionality to validate and extract user information such as username and display name
// from incoming requests, ensuring the data's integrity and correctness before any database operations
// are performed.

package user

import (
	"fmt"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// ValidateUsername validates and extracts username from requestData.
func ValidateUsername(ctx *fasthttp.RequestCtx, requestData map[string]interface{}) (string, error) {
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		zap.L().Error("Invalid username type")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid username type"}`)
		return "", fmt.Errorf("invalid or missing username")
	}
	return username, nil
}

// ValidateUsernameAndDisplayname validates and extracts username and displayname from requestData.
func ValidateUsernameAndDisplayname(
	ctx *fasthttp.RequestCtx,
	requestData map[string]interface{},
) (string, string, error) {
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

// ExtractUsername extracts and validates the username from requestData.
func ExtractUsername(ctx *fasthttp.RequestCtx, requestData map[string]interface{}) (string, bool) {
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Username is required and must be a string"}`)
		return "", false
	}
	return username, true
}
