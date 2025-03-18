package types

import (
	"database/sql"

	"github.com/go-redis/redis/v8"
)

type Persistance struct {
	Db    *sql.DB
	Cache *redis.Client
}
