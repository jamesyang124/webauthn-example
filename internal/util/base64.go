// Package util provides utility functions for base64 encoding/decoding for the WebAuthn example.
package util

import (
	"encoding/base64"

	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
)

// EncodeRawURLEncoding encodes bytes to a base64.RawURLEncoding string.
func EncodeRawURLEncoding(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// DecodeRawURLEncoding decodes a base64.RawURLEncoding string to bytes.
func DecodeRawURLEncoding(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// DecodeCredentialID decodes a credential ID from base64.RawURLEncoding and handles errors.
func DecodeCredentialID(ctx *fasthttp.RequestCtx, encoded string) ([]byte, bool) {
	decoded, err := DecodeRawURLEncoding(encoded)
	if err != nil {
		types.RespondWithError(
			ctx,
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to decode webauthn credential id"}`,
			"Error decoding webauthn credential id",
			err,
		)
		return nil, false
	}
	return decoded, true
}

// DecodeCredentialPublicKey decodes a credential public key from base64.RawURLEncoding and handles errors.
func DecodeCredentialPublicKey(ctx *fasthttp.RequestCtx, encoded string) ([]byte, bool) {
	decoded, err := DecodeRawURLEncoding(encoded)
	if err != nil {
		types.RespondWithError(
			ctx,
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to decode public key"}`,
			"Error decoding public key",
			err,
		)
		return nil, false
	}
	return decoded, true
}
