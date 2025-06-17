// Package user provides user-related validation logic for WebAuthn flows.
package user

import (
	"fmt"

	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/valyala/fasthttp"
)

// ValidateUsername validates and extracts username from requestData using TryIO.
func ValidateUsername(ctx *fasthttp.RequestCtx, requestData map[string]interface{}, username *string) (string, error) {
	user, ok := requestData["username"].(string)
	if !ok || user == "" {
		return "", weberror.UsernameValidationError(
			fmt.Errorf("invalid or missing username"),
		)
	}
	*username = user
	return user, nil
}

// ValidateUsernameAndDisplayname validates and extracts username and displayname from requestData.
func ValidateUsernameAndDisplayname(
	ctx *fasthttp.RequestCtx,
	requestData map[string]interface{},
) (string, string, error) {
	username, ok := requestData["username"].(string)
	if !ok || username == "" {
		return "", "", weberror.UsernameValidationError(
			fmt.Errorf("invalid or missing username"),
		)
	}
	displayname, ok := requestData["displayname"].(string)
	if !ok || displayname == "" {
		return "", "", weberror.DisplayNameValidationError(
			fmt.Errorf("invalid or missing displayname"),
		)
	}
	return username, displayname, nil
}
