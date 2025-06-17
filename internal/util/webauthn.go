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
	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/valyala/fasthttp"
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
		appErr := weberror.WebAuthnBeginRegistrationError(err)
		httpErr := weberror.ToHTTPError(appErr)
		httpErr.RespondAndLog(ctx)
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
		appErr := weberror.WebAuthnFinishRegistrationError(err)
		httpErr := weberror.ToHTTPError(appErr)
		httpErr.RespondAndLog(ctx)
		return nil, false
	}
	return credential, true
}

// BeginLogin wraps WebAuthn.BeginLogin using TryIO pattern.
func BeginLogin(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
	beginLoginResponse *types.BeginLoginResponse,
) (*types.BeginLoginResponse, error) {

	options, sessionData, err := WebAuthn.BeginLogin(user)
	if err != nil {
		return nil, weberror.WebAuthnBeginLoginError(err).Log()
	}
	*beginLoginResponse = types.BeginLoginResponse{
		Options:     options,
		SessionData: sessionData,
	}
	return beginLoginResponse, nil
}

// FinishLogin wraps WebAuthn.FinishLogin and handles errors.
func FinishLogin(
	ctx *fasthttp.RequestCtx,
	user *types.WebAuthnUser,
	sessionData webauthn.SessionData,
	httpRequest *http.Request,
) (*webauthn.Credential, error) {
	credential, err := WebAuthn.FinishLogin(user, sessionData, httpRequest)
	if err != nil {
		return nil, weberror.WebAuthnFinishLoginError(err).Log()
	}
	return credential, nil
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

// NewWebAuthnUserWithCredential creates a WebAuthnUser with a credential using TryIO pattern.
func NewWebAuthnUserWithCredential(id, name, displayName string, credentialID, credentialPublicKey []byte) (*types.WebAuthnUser, error) {

	if len(credentialID) == 0 {
		return nil, weberror.ErrCredentialIDEmpty
	}
	if len(credentialPublicKey) == 0 {
		return nil, weberror.ErrCredentialPublicKeyEmpty
	}
	if id == "" || name == "" || displayName == "" {
		return nil, weberror.ErrUserFieldsEmpty
	}
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
	}, nil
}

// NewWebAuthnUserWithBackupEligible creates a WebAuthnUser with a credential and BackupEligible=true.
func NewWebAuthnUserWithBackupEligible(
	id, name, displayName string,
	credentialID, credentialPublicKey []byte,
	backupEligible bool,
) (*types.WebAuthnUser, error) {
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
	}, nil
}
