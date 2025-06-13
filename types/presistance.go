// Package types defines shared types and response helpers for the WebAuthn example application.
package types

import (
	"database/sql"

	"github.com/go-redis/redis/v8"
)

// Persistance provides the Persistance struct for database and cache connections.
type Persistance struct {
	Db    *sql.DB
	Cache *redis.Client
}
