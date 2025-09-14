package routers

import (
	"virtual_hole_api/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

func AuthRouter(server *gin.Engine) {

	server.POST("/authentication/registration", handlers.RegisterUser)
	server.POST("/authentication/login", handlers.Login)
	// server.GET("/authentication/user/:id", utils.GetUser)

}
