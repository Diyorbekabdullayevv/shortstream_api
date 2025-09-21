// @title Authentication API
// @version 1.0
// @description API for ShortStream project
// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
package main

import (
	"fmt"
	"os"
	docs "virtual_hole_api/docs" // replace with actual module name
	"virtual_hole_api/internal/api/routers"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		fmt.Println("Failed to LOAD environment variables:", err)
		return
	}

	server := gin.Default()

	docs.SwaggerInfo.BasePath = "/"
	server.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	routers.Router(server)

	apiPort := os.Getenv("API_PORT")
	server.Run(apiPort)
}
