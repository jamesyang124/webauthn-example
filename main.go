package main

import (
	"database/sql"
	"log"
	"os"

	// Import without alias
	"github.com/joho/godotenv" // Import godotenv package
	_ "github.com/lib/pq"      // Import PostgreSQL driver
	"github.com/valyala/fasthttp"
)

func main() {
	// Initialize logger
	logger := log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

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

	// Ensure PrepareRoutes is defined in the same package (main)
	routes := PrepareRoutes(db, logger)

	// Start the server
	logger.Println("Starting server on :8080")
	if err := fasthttp.ListenAndServe(":8080", routes.Handler); err != nil {
		logger.Printf("Error in ListenAndServe: %s", err)
	}
}
