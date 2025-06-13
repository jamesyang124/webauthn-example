package main

import (
	"database/sql"
	"os"

	// Import without alias
	"context"

	"github.com/go-redis/redis/v8" // Import Redis package
	"github.com/jamesyang124/webauthn-example/internal/util"
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/joho/godotenv" // Import godotenv package
	_ "github.com/lib/pq"      // Import PostgreSQL driver
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

func main() {

	// Initialize zap logger
	logger, _ := zap.NewProduction()
	zap.ReplaceGlobals(logger)
	defer func() {
		if err := logger.Sync(); err != nil {
			zap.L().Error("Error syncing logger", zap.Error(err))
		}
	}()

	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		zap.L().Error("Error loading .env file", zap.Error(err))
		return
	}

	// Initialize database connection
	connStr := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		zap.L().Error("Failed to connect to database", zap.Error(err))
		return
	}
	defer db.Close()

	// Initialize Redis client
	redisAddr := os.Getenv("REDIS_URL")
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	defer redisClient.Close()

	// Test Redis connection
	ctx := context.Background()
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		zap.L().Error("Failed to connect to Redis", zap.Error(err))
		return
	}

	presistance := new(types.Persistance)
	presistance.Db = db
	presistance.Cache = redisClient

	util.InitWebAuthn()

	// Pass presistance to PrepareRoutes
	routesHandler := PrepareRoutes(presistance)

	// Start the server
	zap.L().Info("Starting server on :8080")
	fasthttpServer := &fasthttp.Server{
		Logger:  nil,
		Handler: routesHandler,
	}

	if err := fasthttpServer.ListenAndServe(":8080"); err != nil {
		zap.L().Error("Error in ListenAndServe", zap.Error(err))
	}
}
