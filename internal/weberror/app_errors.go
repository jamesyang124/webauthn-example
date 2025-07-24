package weberror

import (
	"fmt"

	"go.uber.org/zap"
)

// AppError represents a pure application error with logging capability
type AppError struct {
	Code   string      // Error code for identification
	LogMsg string      // Message for logging
	Err    error       // Underlying error
	Fields []zap.Field // Additional logging fields
}

// Error implements the error interface
func (a *AppError) Error() string {
	if a.Err != nil {
		return fmt.Sprintf("%s: %v", a.LogMsg, a.Err)
	}
	return a.LogMsg
}

// Unwrap returns the underlying error for error unwrapping
func (a *AppError) Unwrap() error {
	return a.Err
}

// Log logs the application error with structured fields
func (a *AppError) Log() *AppError {
	fields := append(a.Fields, zap.String("error_code", a.Code))
	if a.Err != nil {
		fields = append(fields, zap.Error(a.Err))
	}
	zap.L().Error(a.LogMsg, fields...)
	return a
}

// WithField adds additional logging fields
func (a *AppError) WithField(key string, value interface{}) *AppError {
	newErr := *a // copy
	newErr.Fields = append(newErr.Fields, zap.Any(key, value))
	return &newErr
}

// NewAppError creates a new application error
func NewAppError(code, logMsg string, err error) *AppError {
	return &AppError{
		Code:   code,
		LogMsg: logMsg,
		Err:    err,
		Fields: []zap.Field{},
	}
}

// Pre-defined application error instances (singletons)
var (
	// Credential Decode Errors
	ErrCredentialIDDecode = &AppError{
		Code:   "CREDENTIAL_ID_DECODE_ERROR",
		LogMsg: "Failed to decode credential ID",
		Fields: []zap.Field{zap.String("component", "base64")},
	}

	ErrCredentialPublicKeyDecode = &AppError{
		Code:   "CREDENTIAL_PUBLIC_KEY_DECODE_ERROR",
		LogMsg: "Failed to decode credential public key",
		Fields: []zap.Field{zap.String("component", "base64")},
	}

	// JSON Errors
	ErrJSONParse = &AppError{
		Code:   "JSON_PARSE_ERROR",
		LogMsg: "Failed to parse JSON payload",
		Fields: []zap.Field{zap.String("component", "json")},
	}

	ErrJSONMarshal = &AppError{
		Code:   "JSON_MARSHAL_ERROR",
		LogMsg: "Failed to marshal response to JSON",
		Fields: []zap.Field{zap.String("component", "json")},
	}

	// Validation Errors
	ErrUsernameValidation = &AppError{
		Code:   "USERNAME_VALIDATION_ERROR",
		LogMsg: "Username validation failed",
		Fields: []zap.Field{zap.String("component", "validation")},
	}

	ErrDisplayNameValidation = &AppError{
		Code:   "DISPLAYNAME_VALIDATION_ERROR",
		LogMsg: "Displayname validation failed",
		Fields: []zap.Field{zap.String("component", "validation")},
	}

	ErrCredentialIDEmpty = &AppError{
		Code:   "CREDENTIAL_ID_EMPTY_ERROR",
		LogMsg: "Credential ID cannot be empty",
		Fields: []zap.Field{zap.String("component", "validation")},
	}

	ErrCredentialPublicKeyEmpty = &AppError{
		Code:   "CREDENTIAL_PUBLIC_KEY_EMPTY_ERROR",
		LogMsg: "Credential public key cannot be empty",
		Fields: []zap.Field{zap.String("component", "validation")},
	}

	ErrUserFieldsEmpty = &AppError{
		Code:   "USER_FIELDS_EMPTY_ERROR",
		LogMsg: "User ID, name, and display name cannot be empty",
		Fields: []zap.Field{zap.String("component", "validation")},
	}

	// Database Errors
	ErrUserNotFound = &AppError{
		Code:   "USER_NOT_FOUND_ERROR",
		LogMsg: "User not found in database",
		Fields: []zap.Field{zap.String("component", "database")},
	}

	ErrDatabaseQuery = &AppError{
		Code:   "DATABASE_QUERY_ERROR",
		LogMsg: "Database query failed",
		Fields: []zap.Field{zap.String("component", "database")},
	}

	ErrDatabaseUpdate = &AppError{
		Code:   "DATABASE_UPDATE_ERROR",
		LogMsg: "Database update failed",
		Fields: []zap.Field{zap.String("component", "database")},
	}

	// WebAuthn Errors
	ErrWebAuthnBeginLogin = &AppError{
		Code:   "WEBAUTHN_BEGIN_LOGIN_ERROR",
		LogMsg: "Failed to begin WebAuthn login",
		Fields: []zap.Field{zap.String("component", "webauthn")},
	}

	ErrWebAuthnFinishLogin = &AppError{
		Code:   "WEBAUTHN_FINISH_LOGIN_ERROR",
		LogMsg: "Failed to finish WebAuthn login",
		Fields: []zap.Field{zap.String("component", "webauthn")},
	}

	// Redis Errors
	ErrRedisSet = &AppError{
		Code:   "REDIS_SET_ERROR",
		LogMsg: "Failed to set data in Redis",
		Fields: []zap.Field{zap.String("component", "redis")},
	}

	// Redis Errors
	ErrRedisGet = &AppError{
		Code:   "REDIS_GET_ERROR",
		LogMsg: "Failed to get data in Redis",
		Fields: []zap.Field{zap.String("component", "redis")},
	}

	// http request conversion Errors
	ErrRequestConversion = &AppError{
		Code:   "REQUEST_CONVERSION_ERROR",
		LogMsg: "Failed to convert http request",
		Fields: []zap.Field{zap.String("component", "fasthttp")},
	}

	// WebAuthn Registration Errors
	ErrWebAuthnBeginRegistration = &AppError{
		Code:   "WEBAUTHN_BEGIN_REGISTRATION_ERROR",
		LogMsg: "Failed to begin WebAuthn registration",
		Fields: []zap.Field{zap.String("component", "webauthn")},
	}

	ErrWebAuthnFinishRegistration = &AppError{
		Code:   "WEBAUTHN_FINISH_REGISTRATION_ERROR",
		LogMsg: "Failed to finish WebAuthn registration",
		Fields: []zap.Field{zap.String("component", "webauthn")},
	}

	// UUID Generation Errors
	ErrUUIDGeneration = &AppError{
		Code:   "UUID_GENERATION_ERROR",
		LogMsg: "Failed to generate UUID",
		Fields: []zap.Field{zap.String("component", "uuid")},
	}

	// Credential Data Errors
	ErrCredentialDataInvalid = &AppError{
		Code:   "CREDENTIAL_DATA_INVALID_ERROR",
		LogMsg: "Invalid credential data format",
		Fields: []zap.Field{zap.String("component", "webauthn")},
	}

	// Generic Unexpected Errors
	ErrUnexpected = &AppError{
		Code:   "UNEXPECTED_ERROR",
		LogMsg: "Unexpected internal error",
		Fields: []zap.Field{zap.String("component", "application")},
	}
)

// Helper functions to create application errors with underlying errors

// CredentialDecodeError creates a credential ID decode error
func CredentialDecodeError(err error) *AppError {
	newErr := *ErrCredentialIDDecode // copy
	newErr.Err = err
	return &newErr
}

// CredentialPublicKeyDecodeError creates a credential public key decode error
func CredentialPublicKeyDecodeError(err error) *AppError {
	newErr := *ErrCredentialPublicKeyDecode // copy
	newErr.Err = err
	return &newErr
}

// JSONParseError creates a JSON parse error
func JSONParseError(err error) *AppError {
	newErr := *ErrJSONParse // copy
	newErr.Err = err
	return &newErr
}

// JSONMarshalError creates a JSON marshal error
func JSONMarshalError(err error) *AppError {
	newErr := *ErrJSONMarshal // copy
	newErr.Err = err
	return &newErr
}

// UsernameValidationError creates a username validation error
func UsernameValidationError(err error) *AppError {
	newErr := *ErrUsernameValidation // copy
	newErr.Err = err
	return &newErr
}

// DisplayNameValidationError creates a username validation error
func DisplayNameValidationError(err error) *AppError {
	newErr := *ErrDisplayNameValidation // copy
	newErr.Err = err
	return &newErr
}

// UserNotFoundError creates a user not found error
func UserNotFoundError(err error, operation string) *AppError {
	newErr := *ErrUserNotFound // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("operation", operation))
	return &newErr
}

// DatabaseQueryError creates a database query error
func DatabaseQueryError(err error, operation string) *AppError {
	newErr := *ErrDatabaseQuery // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("operation", operation))
	return &newErr
}

// DatabaseUpdateError creates a database update error
func DatabaseUpdateError(err error, operation string) *AppError {
	newErr := *ErrDatabaseUpdate // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("operation", operation))
	return &newErr
}

// WebAuthnBeginLoginError creates a WebAuthn begin login error
func WebAuthnBeginLoginError(err error) *AppError {
	newErr := *ErrWebAuthnBeginLogin // copy
	newErr.Err = err
	return &newErr
}

// WebAuthnFinishLoginError creates a WebAuthn finish login error
func WebAuthnFinishLoginError(err error) *AppError {
	newErr := *ErrWebAuthnFinishLogin // copy
	newErr.Err = err
	return &newErr
}

// RedisSessionSetError creates a Redis set operation error
func RedisSessionSetError(err error, key string) *AppError {
	newErr := *ErrRedisSet // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("key", key))
	return &newErr
}

// RedisSessionGetError creates a Redis get operation error
func RedisSessionGetError(err error, key string) *AppError {
	newErr := *ErrRedisGet // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("key", key))
	return &newErr
}

// RedisSessionError creates a Redis session operation error
func RedisSessionError(err error, key string) *AppError {
	newErr := *ErrRedisSet // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("key", key))
	return &newErr
}

// RequestConversionError creates a request conversion error
func RequestConversionError(err error) *AppError {
	newErr := *ErrRequestConversion // copy
	newErr.Err = err
	return &newErr
}

// WebAuthnBeginRegistrationError creates a WebAuthn begin registration error
func WebAuthnBeginRegistrationError(err error) *AppError {
	newErr := *ErrWebAuthnBeginRegistration // copy
	newErr.Err = err
	return &newErr
}

// WebAuthnFinishRegistrationError creates a WebAuthn finish registration error
func WebAuthnFinishRegistrationError(err error) *AppError {
	newErr := *ErrWebAuthnFinishRegistration // copy
	newErr.Err = err
	return &newErr
}

// UUIDGenerationError creates a UUID generation error
func UUIDGenerationError(err error) *AppError {
	newErr := *ErrUUIDGeneration // copy
	newErr.Err = err
	return &newErr
}

// CredentialDataInvalidError creates a credential data invalid error
func CredentialDataInvalidError(err error) *AppError {
	newErr := *ErrCredentialDataInvalid // copy
	newErr.Err = err
	return &newErr
}

// UnexpectedError creates an unexpected error with context
func UnexpectedError(err error, context string) *AppError {
	newErr := *ErrUnexpected // copy
	newErr.Err = err
	newErr.Fields = append(newErr.Fields, zap.String("context", context))
	return &newErr
}
