// Package util provides utility functions for JSON operations for the WebAuthn example.
package util

import (
	"encoding/json"

	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// ParseJSONBody parses the JSON body from fasthttp.RequestCtx into the provided struct pointer.
func ParseJSONBody(ctx *fasthttp.RequestCtx, v interface{}) error {
	err := json.Unmarshal(ctx.PostBody(), v)
	if err != nil {
		types.RespondWithError(ctx, fasthttp.StatusBadRequest, "Invalid JSON", "Error unmarshaling JSON payload", err)
		return err
	}
	return nil
}

// MarshalAndRespondOnError marshals the given value and handles error response if marshalling fails.
func MarshalAndRespondOnError(ctx *fasthttp.RequestCtx, v interface{}) ([]byte, error) {
	responseJSON, err := json.Marshal(v)
	if err != nil {
		types.RespondWithError(
			ctx,
			fasthttp.StatusInternalServerError,
			"Failed to marshal response",
			"Error marshaling response",
			err,
		)
		return nil, err
	}
	return responseJSON, nil
}

// UnmarshalAndRespondOnError unmarshals JSON and handles error response/logging.
func UnmarshalAndRespondOnError(ctx *fasthttp.RequestCtx, data []byte, v interface{}) bool {
	err := json.Unmarshal(data, v)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to parse session data"}`)
		zap.L().Error("Error parsing session data", zap.Error(err))
		return false
	}
	return true
}
