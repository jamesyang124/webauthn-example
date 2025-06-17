package weberror

import (
	"database/sql"

	"github.com/valyala/fasthttp"
)

// HTTPError represents an HTTP response error
type HTTPError struct {
	StatusCode int       // HTTP status code
	Message    string    // JSON message to send to client
	AppErr     *AppError // Underlying application error
}

// Error implements the error interface
func (h *HTTPError) Error() string {
	if h.AppErr != nil {
		return h.AppErr.Error()
	}
	return h.Message
}

// Unwrap returns the underlying application error
func (h *HTTPError) Unwrap() error {
	return h.AppErr
}

// RespondAndLog sets the HTTP response and logs the application error
func (h *HTTPError) RespondAndLog(ctx *fasthttp.RequestCtx) {
	// Set HTTP response
	ctx.SetStatusCode(h.StatusCode)
	ctx.SetContentType("application/json")
	ctx.SetBodyString(h.Message)

	// Log the application error if present
	if h.AppErr != nil {
		h.AppErr.Log()
	}
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(statusCode int, message string, appErr *AppError) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
		AppErr:     appErr,
	}
}

// HTTP error mapping functions - convert application errors to HTTP errors

// ToHTTPError converts an application error to an appropriate HTTP error
func ToHTTPError(appErr *AppError) *HTTPError {
	if appErr == nil {
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Internal server error"}`,
			nil,
		)
	}

	switch appErr.Code {
	// Client errors (4xx)
	case "JSON_PARSE_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Invalid JSON"}`,
			appErr,
		)

	case "USERNAME_VALIDATION_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Invalid username type"}`,
			appErr,
		)

	case "DISPLAYNAME_VALIDATION_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Invalid displayname type"}`,
			appErr,
		)

	case "CREDENTIAL_ID_EMPTY_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Credential ID cannot be empty"}`,
			appErr,
		)

	case "CREDENTIAL_PUBLIC_KEY_EMPTY_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Credential public key cannot be empty"}`,
			appErr,
		)

	case "USER_FIELDS_EMPTY_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "User ID, name, and display name cannot be empty"}`,
			appErr,
		)

	case "USER_NOT_FOUND_ERROR":
		return NewHTTPError(
			fasthttp.StatusNotFound,
			`{"error": "User not found"}`,
			appErr,
		)

	// Server errors (5xx)
	case "CREDENTIAL_ID_DECODE_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to decode webauthn credential id"}`,
			appErr,
		)

	case "CREDENTIAL_PUBLIC_KEY_DECODE_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to decode public key"}`,
			appErr,
		)

	case "JSON_MARSHAL_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to marshal response"}`,
			appErr,
		)

	case "DATABASE_QUERY_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Database error"}`,
			appErr,
		)

	case "DATABASE_UPDATE_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Database error"}`,
			appErr,
		)

	case "WEBAUTHN_BEGIN_LOGIN_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to begin WebAuthn login"}`,
			appErr,
		)

	case "WEBAUTHN_FINISH_LOGIN_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to finish WebAuthn login"}`,
			appErr,
		)

	case "REDIS_SET_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to persist session data"}`,
			appErr,
		)

	case "REDIS_GET_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to get session data"}`,
			appErr,
		)

	case "REQUEST_CONVERSION_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to coonvert request"}`,
			appErr,
		)

	case "WEBAUTHN_BEGIN_REGISTRATION_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to begin WebAuthn registration"}`,
			appErr,
		)

	case "WEBAUTHN_FINISH_REGISTRATION_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Verification failed"}`,
			appErr,
		)

	case "UUID_GENERATION_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Failed to generate user ID"}`,
			appErr,
		)

	case "CREDENTIAL_DATA_INVALID_ERROR":
		return NewHTTPError(
			fasthttp.StatusBadRequest,
			`{"error": "Invalid credential data"}`,
			appErr,
		)

	case "UNEXPECTED_ERROR":
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Internal server error"}`,
			appErr,
		)

	// Default to internal server error
	default:
		return NewHTTPError(
			fasthttp.StatusInternalServerError,
			`{"error": "Internal server error"}`,
			appErr,
		)
	}
}

// Helper functions for common patterns

// HandleDatabaseError intelligently handles database errors
func HandleDatabaseError(err error, operation string) *HTTPError {
	if err == sql.ErrNoRows {
		appErr := UserNotFoundError(err, operation)
		return ToHTTPError(appErr)
	}

	appErr := DatabaseQueryError(err, operation)
	return ToHTTPError(appErr)
}
