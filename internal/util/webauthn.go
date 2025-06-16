// Package util provides utility functions for JSON, base64, and WebAuthn operations.
//
// This package includes functions to initialize WebAuthn, begin and finish
// registration and login processes, and create WebAuthnUser instances. It is
// meant to be used internally within the webauthn-example application.
package util

import (
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

var (
	WebAuthn     *webauthn.WebAuthn
	RegisterTmpl *template.Template
	once         sync.Once
)

// InitWebAuthn initializes the WebAuthn instance with the correct config.
func InitWebAuthn() {
	once.Do(func() {
		var err error
		WebAuthn, err = webauthn.New(&webauthn.Config{
			RPDisplayName: "Example Corp",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost:8080"},
		})
		if err != nil {
			log.Fatalf("failed to create WebAuthn instance: %v", err)
		}
	})
}

// BeginRegistration wraps WebAuthn.BeginRegistration and handles errors.
func BeginRegistration(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
) (options *protocol.CredentialCreation, sessionData *webauthn.SessionData, ok bool) {
	options, sessionData, err := WebAuthn.BeginRegistration(user)
	if err != nil {
		zap.L().Error("Failed to begin WebAuthn registration", zap.Error(err))
		types.RespondWithError(
			ctx,
			fasthttp.StatusInternalServerError,
			"Failed to begin WebAuthn registration",
			"Error beginning WebAuthn registration",
			err,
		)
		return nil, nil, false
	}
	return options, sessionData, true
}

// FinishRegistration wraps WebAuthn.FinishRegistration and handles errors.
func FinishRegistration(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
	sessionData webauthn.SessionData,
	httpRequest *http.Request,
) (credential *webauthn.Credential, ok bool) {
	credential, err := WebAuthn.FinishRegistration(user, sessionData, httpRequest)
	if err != nil {
		zap.L().Error("Error finishing WebAuthn registration", zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Verification failed"}`)
		return nil, false
	}
	return credential, true
}

// BeginLogin wraps WebAuthn.BeginLogin and handles errors.
func BeginLogin(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
) (options *protocol.CredentialAssertion, sessionData *webauthn.SessionData, ok bool) {
	options, sessionData, err := WebAuthn.BeginLogin(user)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to begin WebAuthn login"}`)
		zap.L().Error("Error beginning WebAuthn login", zap.Error(err))
		return nil, nil, false
	}
	return options, sessionData, true
}

// FinishLogin wraps WebAuthn.FinishLogin and handles errors.
func FinishLogin(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
	sessionData webauthn.SessionData,
	httpRequest *http.Request,
) (credential *webauthn.Credential, ok bool) {
	credential, err := WebAuthn.FinishLogin(user, sessionData, httpRequest)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Login verification failed"}`)
		zap.L().Error("Error finishing WebAuthn login", zap.Error(err))
		return nil, false
	}
	return credential, true
}

// NewWebAuthnUser creates a WebAuthnUser with no credentials.
func NewWebAuthnUser(id, name, displayName string) *types.WebAuthnUser {
	return &types.WebAuthnUser{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{},
	}
}

// NewWebAuthnUserWithCredential creates a WebAuthnUser with a credential and backup eligibility flag.
func NewWebAuthnUserWithCredential(id, name, displayName string, credentialID, credentialPublicKey []byte) *types.WebAuthnUser {
	return &types.WebAuthnUser{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{
			{
				ID:        credentialID,
				PublicKey: credentialPublicKey,
			},
		},
	}
}

// NewWebAuthnUserWithBackupEligible creates a WebAuthnUser with a credential and BackupEligible=true.
func NewWebAuthnUserWithBackupEligible(
	id, name, displayName string,
	credentialID, credentialPublicKey []byte,
	backupEligible bool,
) *types.WebAuthnUser {
	return &types.WebAuthnUser{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: []webauthn.Credential{
			{
				ID:        credentialID,
				PublicKey: credentialPublicKey,
				Flags: webauthn.CredentialFlags{
					BackupEligible: backupEligible,
				},
			},
		},
	}
}
