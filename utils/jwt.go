package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = os.Getenv("JWT_SECRET_KEY")

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func GenerateTokens(email string, expMins time.Duration) (accessToken string, refreshToken string, err error) {

	var jwtSecretKey = os.Getenv("JWT_SECRET_KEY")
	accessClaims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expMins)),
		},
	}

	accessJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJwt.SignedString([]byte(jwtSecretKey))
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
	refreshToken, err = refreshJwt.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func VerifyToken(tokenStr string, isRefresh bool) (*Claims, error) {
	
	secret := jwtSecretKey
	if isRefresh {
		secret = jwtSecretKey
	}

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}

func GenTknForChecking(email, scope string) (string, error) {

	var jwtSecretKey = os.Getenv("JWT_SECRET_KEY")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"scope": scope,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	return token.SignedString([]byte(jwtSecretKey))
}
