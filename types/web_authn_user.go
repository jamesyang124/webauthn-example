// Package types defines shared types and response helpers for the WebAuthn example application.
package types

import "github.com/go-webauthn/webauthn/webauthn"

type WebAuthnUser struct {
	ID          string
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnName() string {
	return u.Name
}

func (u WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
