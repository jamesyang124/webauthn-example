package session

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// SetWebauthnSessionData stores session data in Redis with a TTL and handles errors and logging.
func SetWebauthnSessionDataWithErrorHandling(ctx *fasthttp.RequestCtx, redisClient *redis.Client, sessionKey string, sessionDataJson []byte, ttl time.Duration) bool {
	err := redisClient.Set(context.Background(), sessionKey, string(sessionDataJson), ttl).Err()
	if err != nil {
		zap.L().Error("Failed to persist session data", zap.Error(err), zap.String("sessionKey", sessionKey))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to persist session data"}`)
		return false
	}
	return true
}

// GetWebauthnSessionData retrieves session data from Redis by key and handles errors and logging.
func GetWebauthnSessionDataWithErrorHandling(ctx *fasthttp.RequestCtx, redisClient *redis.Client, sessionKey string) (string, bool) {
	redisSessionData, err := redisClient.Get(context.Background(), sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			zap.L().Error("Session data not found", zap.String("sessionKey", sessionKey))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(`{"error": "Session data not found"}`)
		} else {
			zap.L().Error("Error retrieving session data", zap.Error(err), zap.String("sessionKey", sessionKey))
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error": "Failed to retrieve session data"}`)
		}
		return "", false
	}
	return redisSessionData, true
}
