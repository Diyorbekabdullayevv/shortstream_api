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

func VerifyUser(ctx *gin.Context, user models.User) (models.User, error) {

	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.User{}, err
	}
	defer db.Close()

	var existingUser models.User
	err = db.QueryRow(`SELECT id, email, password FROM users where email = $1`, user.Email).
		Scan(&existingUser.Id, &existingUser.Email, &existingUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		}
		return models.User{}, err
	}

	if user.Email != existingUser.Email {
		return models.User{}, errors.New("invalid email")
	}

	isValid := CheckHashPassword(user.Password, existingUser.Password)
	if !isValid {
		return models.User{}, errors.New("invalid password")
	}

	return existingUser, nil
}

func GenerateTokens(email string, expMins time.Duration) (accessToken string, refreshToken string, err error) {

	accessClaims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expMins)), 
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
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), 
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

func GenTknForCheckUsername(email string) (string, error) {

	secretKey := "super_secret_key"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"scope": "username_only",
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	return token.SignedString([]byte(secretKey))
}
