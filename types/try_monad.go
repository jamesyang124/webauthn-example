// Package types provides functional programming helpers, including a custom Try monad for IOEither chains.
//
// This file defines a fluent, type-safe TryIOChain for composing error-handling computations using fp-go's IOEither.
// It enables chaining, transformation, and matching of computations that may fail, in a functional style.

package types

import (
	"database/sql"
	"net/http"

	"github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/ioeither"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// TryIO runs a function returning (T, error) and wraps it as an IOEither for functional error handling.
func TryIO[T any](fn func() (T, error)) ioeither.IOEither[error, T] {
	return ioeither.TryCatch(fn, func(e error) error { return e })
}

// TryIOChain is a fluent builder for chaining IOEither computations with type safety.
type TryIOChain[T any] struct {
	computation ioeither.IOEither[error, T]
}

// NewTryIO creates a new TryIOChain from a function returning (T, error).
func NewTryIO[T any](fn func() (T, error)) *TryIOChain[T] {
	return &TryIOChain[T]{
		computation: TryIO(fn),
	}
}

// Match executes the computation and calls onError or onSuccess depending on the result.
func (tc *TryIOChain[T]) Match(onError func(error), onSuccess func(T)) {
	result := tc.computation() // Execute the lazy computation
	either.Fold(
		func(err error) struct{} {
			onError(err)
			return struct{}{}
		},
		func(val T) struct{} {
			onSuccess(val)
			return struct{}{}
		},
	)(result)
}

// ThenTyped allows type transformation while maintaining type safety.
func ThenTyped[T, U any](tc *TryIOChain[T], fn func(T) (U, error)) *TryIOChain[U] {
	return &TryIOChain[U]{
		computation: ioeither.MonadChain(tc.computation, func(val T) ioeither.IOEither[error, U] {
			return ioeither.TryCatch(func() (U, error) {
				return fn(val)
			}, func(e error) error { return e })
		}),
	}
}

// Fluent builder methods for common type transformations

// ThenString transforms to string type.
func (tc *TryIOChain[T]) ThenString(fn func(T) (string, error)) *TryIOChain[string] {
	return ThenTyped(tc, fn)
}

// ThenHttpRequest transforms to http request type.
func (tc *TryIOChain[T]) ThenHttpRequest(fn func(T) (*http.Request, error)) *TryIOChain[*http.Request] {
	return ThenTyped(tc, fn)
}

// ThenBytes transforms to []byte type.
func (tc *TryIOChain[T]) ThenBytes(fn func(T) ([]byte, error)) *TryIOChain[[]byte] {
	return ThenTyped(tc, fn)
}

// ThenAny transforms to any type.
func (tc *TryIOChain[T]) ThenAny(fn func(T) (any, error)) *TryIOChain[any] {
	return ThenTyped(tc, fn)
}

// ThenWebAuthnUserPtr transforms to *WebAuthnUser type.
func (tc *TryIOChain[T]) ThenWebAuthnUser(fn func(T) (*WebAuthnUser, error)) *TryIOChain[*WebAuthnUser] {
	return ThenTyped(tc, fn)
}

func (tc *TryIOChain[T]) ThenWebAuthnCredential(fn func(T) (*webauthn.Credential, error)) *TryIOChain[*webauthn.Credential] {
	return ThenTyped(tc, fn)
}

func (tc *TryIOChain[T]) ThenSQLResult(fn func(T) (sql.Result, error)) *TryIOChain[sql.Result] {
	return ThenTyped(tc, fn)
}

// ThenBeginLoginResponse transforms to *BeginLoginResponse type.
func (tc *TryIOChain[T]) ThenBeginLoginResponse(fn func(T) (*BeginLoginResponse, error)) *TryIOChain[*BeginLoginResponse] {
	return ThenTyped(tc, fn)
}

// ThenUUID transforms to uuid.UUID type.
func (tc *TryIOChain[T]) ThenUUID(fn func(T) (uuid.UUID, error)) *TryIOChain[uuid.UUID] {
	return ThenTyped(tc, fn)
}

// ThenWebAuthnSessionData transforms to webauthn.SessionData type.
func (tc *TryIOChain[T]) ThenWebAuthnSessionData(fn func(T) (webauthn.SessionData, error)) *TryIOChain[webauthn.SessionData] {
	return ThenTyped(tc, fn)
}

// ThenCredentialCreation transforms to *protocol.CredentialCreation type.
func (tc *TryIOChain[T]) ThenCredentialCreation(fn func(T) (*protocol.CredentialCreation, error)) *TryIOChain[*protocol.CredentialCreation] {
	return ThenTyped(tc, fn)
}

// ThenInt64 transforms to int64 type.
func (tc *TryIOChain[T]) ThenInt64(fn func(T) (int64, error)) *TryIOChain[int64] {
	return ThenTyped(tc, fn)
}
