package main

import (
	"fmt"
	"os"
	"virtual_hole_api/internal/api/routers"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		fmt.Println("Failed to LOAD environment variables:", err)
		return
	}

	server := gin.Default()

	routers.Router(server)

	apiPort := os.Getenv("API_PORT")
	server.Run(apiPort)
}
