package routers

import (
	"virtual_hole_api/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

func AuthRouter(server *gin.Engine) {

	server.POST("/authentication/registration", handlers.RegisterUser)
	server.POST("/authentication/login", handlers.LoginUser)
	server.PUT("/authentication/resend_code", handlers.ResendCode)
	server.POST("/authentication/code_confirmation", handlers.ConfirmCode) //? should be turned into a middleware
	server.POST("/authentication/create_username", handlers.CreateUsername)
	server.PUT("/authentication/change_username", handlers.ChangeUsername)
	server.PUT("/authentication/forgot_password", handlers.ForgotPassword)
	server.POST("/authentication/confirm_code_password", handlers.ConfirmCodeResetPassword) //? should be turned into a middleware
	server.PUT("/authentication/reset_password", handlers.ResetPassword)
	server.GET("/authentication/login_with_google", handlers.LoginWithGoogle) //! must be changed to POST method
	server.GET("/authentication/register_with_google", handlers.RegisterWithGoogle) //! must be changed to POST method

}
