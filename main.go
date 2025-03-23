package main

import (
	"database/sql"
	"log"
	"os"

	// Import without alias
	"context"

	"github.com/go-redis/redis/v8" // Import Redis package
	"github.com/jamesyang124/webauthn-example/types"
	"github.com/joho/godotenv" // Import godotenv package
	_ "github.com/lib/pq"      // Import PostgreSQL driver
	"github.com/valyala/fasthttp"
)

func main() {
	// Initialize logger
	logger := log.New(os.Stdout, "INFO: ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		logger.Printf("Error loading .env file: %s", err)
		return
	}

	// Initialize database connection
	connStr := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logger.Printf("Failed to connect to database: %s", err)
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
		logger.Printf("Failed to connect to Redis: %s", err)
		return
	}

	presistance := new(types.Persistance)
	presistance.Db = db
	presistance.Cache = redisClient

	// Pass presistance to PrepareRoutes
	routesHandler := PrepareRoutes(logger, presistance)

	// Start the server
	logger.Println("Starting server on :8080")
	fasthttpServer := &fasthttp.Server{
		Logger:  logger,
		Handler: routesHandler,
	}
	if err := fasthttpServer.ListenAndServe(":8080"); err != nil {
		logger.Printf("Error in ListenAndServe: %s", err)
	}
}
