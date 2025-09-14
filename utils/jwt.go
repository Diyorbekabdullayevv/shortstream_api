package utils

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var accessSecret = []byte("super-secret-access")   // should be in env variable
var refreshSecret = []byte("super-secret-refresh") // should be in env variable

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func VerifyUser(ctx *gin.Context, user models.RegisterUser) (models.RegisterUser, error) {

	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.RegisterUser{}, err
	}
	defer db.Close()

	var existingUser models.RegisterUser
	err = db.QueryRow(`SELECT id, fullname, email, password FROM RegisterUser where email = $1`, user.Email).
		Scan(&existingUser.Id, &existingUser.FullName, &existingUser.Email, &existingUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		}
		return models.RegisterUser{}, err
	}

	if user.Email != existingUser.Email {
		return models.RegisterUser{}, errors.New("invalid email")
	}

	isValid := CheckHashPassword(user.Password, existingUser.Password)
	if !isValid {
		return models.RegisterUser{}, errors.New("invalid password")
	}

	return existingUser, nil
}

func GenerateTokens(email string) (accessToken string, refreshToken string, err error) {

	accessClaims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // short
		},
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString(accessSecret)
	if err != nil {
		return "", "", err
	}

	refreshClaims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
		},
	}

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshJwt.SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func VerifyToken(tokenStr string, isRefresh bool) (*Claims, error) {
	secret := accessSecret
	if isRefresh {
		secret = refreshSecret
	}

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}
