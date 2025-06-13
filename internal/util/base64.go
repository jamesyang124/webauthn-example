// Package util provides utility functions for base64 encoding/decoding for the WebAuthn example.
package util

import (
	"encoding/base64"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
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
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode webauthn credential id"}`)
		zap.L().Error("Error decoding webauthn credential id", zap.Error(err))
		return nil, false
	}
	return decoded, true
}

// DecodeCredentialPublicKey decodes a credential public key from base64.RawURLEncoding and handles errors.
func DecodeCredentialPublicKey(ctx *fasthttp.RequestCtx, encoded string) ([]byte, bool) {
	decoded, err := DecodeRawURLEncoding(encoded)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to decode public key"}`)
		zap.L().Error("Error decoding public key", zap.Error(err))
		return nil, false
	}
	return decoded, true
}
