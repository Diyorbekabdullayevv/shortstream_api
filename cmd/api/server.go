package main

import (
	"virtual_hole_api/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	server := gin.Default()

	server.POST("/authentication/registration", handlers.RegisterUser)
	server.GET("/authentication/user/:id", handlers.GetUser)

	server.Run(":5000")
}
