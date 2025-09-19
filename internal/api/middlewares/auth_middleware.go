package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthUsername(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	if err != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		fmt.Println("token:", token)
		fmt.Println("Error validating token:", err)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["scope"] != "username_only" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}
	email := claims["email"]
	ctx.Set("email_username", email)
	ctx.Next()
}

func AuthPassword(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	if err != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		fmt.Println("token:", token)
		fmt.Println("Error validating token:", err)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["scope"] != "password_only" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}
	email := claims["email"]
	ctx.Set("email_password", email)
	ctx.Next()
}
