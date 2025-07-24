// Package util provides utility functions for JSON operations for the WebAuthn example.
package util

import (
	"encoding/json"

	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/valyala/fasthttp"
)

// ParseJSONBody parses the JSON body from fasthttp.RequestCtx into the provided struct pointer using TryIO.
func ParseJSONBody(ctx *fasthttp.RequestCtx, v interface{}) (string, error) {
	err := json.Unmarshal(ctx.PostBody(), v)
	if err != nil {
		return "", weberror.JSONParseError(err).Log()
	}
	return "", nil
}

// MarshalAndRespondOnError marshals the given value using TryIO pattern.
func MarshalAndRespondOnError(ctx *fasthttp.RequestCtx, v interface{}) ([]byte, error) {
	responseJSON, err := json.Marshal(v)
	if err != nil {
		return responseJSON, weberror.JSONMarshalError(err).Log()
	}
	return responseJSON, nil
}

// UnmarshalAndRespondOnError unmarshals JSON and handles error response/logging.
func UnmarshalAndRespondOnError(ctx *fasthttp.RequestCtx, data []byte, v interface{}) ([]byte, error) {
	err := json.Unmarshal(data, v)
	if err != nil {
		return data, weberror.JSONParseError(err).Log()
	}
	return data, nil
}
