package weberror

import (
	"fmt"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// WebAuthnError represents a structured error with HTTP status code, user message, and log message
type WebAuthnError struct {
	StatusCode int    // HTTP status code
	Msg        string // Message to send to the user
	LogMsg     string // Message for logging
	Err        error  // Underlying error
}

// Error implements the error interface
func (w *WebAuthnError) Error() string {
	if w.Err != nil {
		return fmt.Sprintf("%s: %v", w.LogMsg, w.Err)
	}
	return w.LogMsg
}

// Unwrap returns the underlying error for error unwrapping
func (w *WebAuthnError) Unwrap() error {
	return w.Err
}

// RespondAndLog sets the HTTP response and logs the error
func (w *WebAuthnError) RespondAndLog(ctx *fasthttp.RequestCtx) {
	// Set HTTP response
	ctx.SetStatusCode(w.StatusCode)
	ctx.SetContentType("application/json")
	ctx.SetBodyString(w.Msg)

	// Log the error
	zap.L().Error(w.LogMsg, zap.Error(w.Err), zap.Int("status", w.StatusCode))
}

// NewWebAuthnError creates a new WebAuthnError
func NewWebAuthnError(statusCode int, msg, logMsg string, err error) *WebAuthnError {
	return &WebAuthnError{
		StatusCode: statusCode,
		Msg:        msg,
		LogMsg:     logMsg,
		Err:        err,
	}
}

// Helper functions for common error types

// NewBadRequestError creates a bad request error
func NewBadRequestError(msg, logMsg string, err error) *WebAuthnError {
	return NewWebAuthnError(fasthttp.StatusBadRequest, msg, logMsg, err)
}

// NewUnauthorizedError creates an unauthorized error
func NewUnauthorizedError(msg, logMsg string, err error) *WebAuthnError {
	return NewWebAuthnError(fasthttp.StatusUnauthorized, msg, logMsg, err)
}

// NewNotFoundError creates a not found error
func NewNotFoundError(msg, logMsg string, err error) *WebAuthnError {
	return NewWebAuthnError(fasthttp.StatusNotFound, msg, logMsg, err)
}

// NewInternalServerError creates an internal server error
func NewInternalServerError(msg, logMsg string, err error) *WebAuthnError {
	return NewWebAuthnError(fasthttp.StatusInternalServerError, msg, logMsg, err)
}

// NewJSONParseError creates a JSON parsing error
func NewJSONParseError(err error) *WebAuthnError {
	return NewBadRequestError(
		`{"error": "Invalid JSON"}`,
		"Error parsing JSON payload",
		err,
	)
}

// NewUsernameValidationError creates a username validation error
func NewUsernameValidationError(err error) *WebAuthnError {
	return NewBadRequestError(
		`{"error": "Invalid username type"}`,
		"Invalid username type",
		err,
	)
}

// NewCredentialDecodeError creates a credential decoding error
func NewCredentialDecodeError(credentialType string, err error) *WebAuthnError {
	return NewInternalServerError(
		fmt.Sprintf(`{"error": "Failed to decode %s"}`, credentialType),
		fmt.Sprintf("Error decoding %s", credentialType),
		err,
	)
}

// NewDatabaseError creates a database error
func NewDatabaseError(operation string, err error) *WebAuthnError {
	if err.Error() == "sql: no rows in result set" {
		return NewNotFoundError(
			`{"error": "User not found"}`,
			fmt.Sprintf("User not found during %s", operation),
			err,
		)
	}
	return NewInternalServerError(
		`{"error": "Database error"}`,
		fmt.Sprintf("Database error during %s", operation),
		err,
	)
}

// NewWebAuthnOperationError creates a WebAuthn operation error
func NewWebAuthnOperationError(operation string, err error) *WebAuthnError {
	return NewInternalServerError(
		fmt.Sprintf(`{"error": "Failed to %s"}`, operation),
		fmt.Sprintf("Error during WebAuthn %s", operation),
		err,
	)
}

// NewRedisError creates a Redis operation error
func NewRedisError(operation string, err error) *WebAuthnError {
	return NewInternalServerError(
		`{"error": "Failed to persist session data"}`,
		fmt.Sprintf("Redis error during %s", operation),
		err,
	)
}