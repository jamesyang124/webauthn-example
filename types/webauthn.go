package types

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type BeginLoginResponse struct {
	Options     *protocol.CredentialAssertion
	SessionData *webauthn.SessionData
}
