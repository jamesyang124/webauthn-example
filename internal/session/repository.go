// Package session provides helpers for managing WebAuthn session data in Redis.
// It includes functions to set and get session data with automatic error handling and logging.
// The session data is stored as JSON and is associated with a TTL (time-to-live) for expiration.
package session

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jamesyang124/webauthn-example/internal/weberror"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// SetWebauthnSessionData stores session data in Redis using TryIO pattern.
func SetWebauthnSessionData(
	ctx *fasthttp.RequestCtx,
	redisClient *redis.Client,
	sessionKey string,
	sessionDataJSON []byte,
	ttl time.Duration,
) ([]byte, error) {
	err := redisClient.Set(context.Background(), sessionKey, string(sessionDataJSON), ttl).Err()
	if err != nil {
		return sessionDataJSON, weberror.RedisSessionSetError(err, sessionKey).Log()
	}
	return sessionDataJSON, nil
}

// GetWebauthnSessionData retrieves session data from Redis by key and handles errors and logging.
func GetWebauthnSessionData(
	ctx *fasthttp.RequestCtx,
	redisClient *redis.Client,
	sessionKey string,
) (string, error) {
	redisSessionData, err := redisClient.Get(context.Background(), sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			zap.L().Error("Session data not found", zap.String("sessionKey", sessionKey))
			return "", weberror.UserNotFoundError(err, "get user from redis").Log()
		}
		return "", weberror.RedisSessionGetError(err, sessionKey).Log()
	}
	return redisSessionData, nil
}
