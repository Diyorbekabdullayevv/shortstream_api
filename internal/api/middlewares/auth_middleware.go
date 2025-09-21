package middlewares

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthUsername(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		ctx.Abort()
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	claims := token.Claims.(jwt.MapClaims)
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token_expired"})
			return
		}
	}

	if err != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		fmt.Println("token:", token)
		fmt.Println("Error validating token:", err)
		return
	}

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
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		ctx.Abort()
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	claims := token.Claims.(jwt.MapClaims)
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token_expired"})
			return
		}
	}

	if err != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		fmt.Println("token:", token)
		fmt.Println("Error validating token:", err)
		return
	}

	if claims["scope"] != "password_only" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	email := claims["email"]
	ctx.Set("email_password", email)
	ctx.Next()
}
