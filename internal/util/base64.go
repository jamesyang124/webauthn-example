// Package util provides utility functions for base64 encoding/decoding for the WebAuthn example.
package util

import (
	"encoding/base64"

	"github.com/jamesyang124/webauthn-example/internal/weberror"
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

// DecodeCredentialID decodes a credential ID from base64.RawURLEncoding using IOEither TryCatch pattern.
func DecodeCredentialID(ctx *fasthttp.RequestCtx, encoded string) ([]byte, error) {

	res, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, weberror.CredentialDecodeError(err).Log()
	}
	return res, nil

}

// DecodeCredentialPublicKey decodes a credential public key from base64.RawURLEncoding using TryIO pattern.
func DecodeCredentialPublicKey(ctx *fasthttp.RequestCtx, encoded string, credentialPublicKey *[]byte) ([]byte, error) {
	decoded, err := DecodeRawURLEncoding(encoded)
	if err != nil {
		return nil, weberror.CredentialPublicKeyDecodeError(err).Log()
	}
	*credentialPublicKey = decoded
	return decoded, nil
}
