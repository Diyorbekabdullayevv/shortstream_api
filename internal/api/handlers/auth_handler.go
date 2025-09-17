package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
	"virtual_hole_api/internal/database/dbhandlers"
	"virtual_hole_api/internal/models"
	"virtual_hole_api/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RegisterUser(ctx *gin.Context) {
	var newUser models.User
	err := ctx.ShouldBindBodyWithJSON(&newUser)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	if len(newUser.FullName) < 3 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println("Invalid username!")
		return
	} else if len(newUser.Email) < 4 || !strings.Contains(newUser.Email, "@") {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println("Invalid email!")
		return
	} else if len(newUser.Password) < 6 || len(newUser.Password) > 320 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println("Invalid password!")
		return
	}

	err = utils.CheckString(newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println(err)
		return
	}

	hashedPassword, err := utils.HashPassword(newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to HASH user password:", err)
		return
	}

	newUser.Password = hashedPassword

	err = dbhandlers.RegisterUserDB(newUser)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SAVE user in the database:", err)
		return
	}

	err = dbhandlers.SavePasswordDB(newUser.Password, newUser.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SAVE password in the database:", err)
		return
	}

	code, err := utils.GenerateCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to GENERATE 6 digit code:", err)
		return
	}

	err = utils.SendEmail(newUser.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SEND 6 digit code to user email:", err)
		return
	}

	err = dbhandlers.StoreOneTimeCodeDB(newUser, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SEND one time code to database:", err)
		return
	}

	userMap := map[string]any{
		"Name:":  newUser.FullName,
		"Email:": newUser.Email,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully registered"})
	ctx.JSON(http.StatusCreated, gin.H{"User:": userMap})
}

func LoginUser(ctx *gin.Context) {

	var user models.User
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	userFromDb, err := utils.VerifyUser(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println("Failed to VERIFY user:", err)
		return
	}

	expMins := 15 * time.Minute

	accessToken, refreshToken, err := utils.GenerateTokens(user.Email, expMins)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println("Failed to GENERATE token:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+accessToken)

	ctx.SetCookie(
		"refresh_token",
		refreshToken,
		7*24*60*60,
		"/",
		"localhost",
		true,
		true,
	)

	device, err := utils.SaveUserDetails(ctx, userFromDb)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user details token:", err)
		return
	}

	tokenMap := map[string]string{
		"token":        accessToken,
		"refreshToken": refreshToken,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully login!"})
	ctx.JSON(http.StatusOK, gin.H{"data": tokenMap})
	ctx.JSON(http.StatusOK, gin.H{"device": device})
}

func ResendCode(ctx *gin.Context) {

	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	exUser, err := dbhandlers.OneTimeCodeGetUserDB(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	allowed, remaining := utils.CanSendCode(exUser.LastCodeSentAt)
	if allowed {
		code, err := utils.GenerateCode()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			fmt.Println("Failed to GENERATE 6 digit code:", err)
			return
		}

		err = utils.SendEmail(user.Email, code)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			fmt.Println("Failed to send email to the user:", err)
			return
		}
		exUser.Code = code
		exUser.LastCodeSentAt = time.Now()
		err = dbhandlers.UpdateOneTimeCodeDB(exUser)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			fmt.Println("Failed to SAVE user to database:", err)
			return
		}

	} else {
		seconds := fmt.Sprintf("Try after %v seconds!", remaining)
		ctx.JSON(http.StatusOK, gin.H{"message": seconds})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"success": "code sent to your email"})
}

func ConfirmCode(ctx *gin.Context) {

	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	exUser, err := dbhandlers.OneTimeCodeGetUserDB(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	if user.Code != exUser.Code {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "invalid code"})
		return
	}

	tokenString, err := utils.GenTknForChecking(user.Email, "username_only")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GEERATE token:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+tokenString)
	ctx.JSON(http.StatusOK, gin.H{"message": "code successfuly confirmed"})
}

func CreateUsername(ctx *gin.Context) {

	var usernameStruct models.Username
	err := ctx.ShouldBindBodyWithJSON(&usernameStruct)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	authHeader := ctx.GetHeader("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	if err != nil || !token.Valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		fmt.Println("token:", token)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["scope"] != "username_only" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "token not allowed for this action"})
		return
	}

	if len(usernameStruct.Username) < 3 || len(usernameStruct.Username) > 56 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username must contain at least 3 to 56 characters!"})
		return
	}

	if !strings.Contains(usernameStruct.Username, ".") || !strings.Contains(usernameStruct.Username, "_") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username must contain both '.' and '_' signs!"})
		return
	}

	exists, err := dbhandlers.CheckUsernameIfExistsDB(usernameStruct.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to CHECK if username exists:", err)
		return
	}

	if exists {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "username already choosen by users"})
		return
	}

	email := claims["email"]
	err = dbhandlers.SaveUsernameDB(usernameStruct.Username, email.(string))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE username to database:", err)
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "username successfully saved"})
}

func ChangeUsername(ctx *gin.Context) {
	var usernameStruct models.Username
	err := ctx.ShouldBindBodyWithJSON(&usernameStruct)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	authHeader := ctx.GetHeader("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	if err != nil || !token.Valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		fmt.Println("token:", token)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["scope"] != "username_only" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "token not allowed for this action"})
		return
	}

	if len(usernameStruct.Username) < 3 || len(usernameStruct.Username) > 56 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username must contain at least 3 to 56 characters!"})
		return
	}

	if !strings.Contains(usernameStruct.Username, ".") || !strings.Contains(usernameStruct.Username, "_") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username must contain both '.' and '_' signs!"})
		return
	}

	exists, err := dbhandlers.CheckUsernameIfExistsDB(usernameStruct.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to CHECK if username exists:", err)
		return
	}

	if exists {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "username already choosen by users"})
		return
	}

	email := claims["email"]
	err = dbhandlers.UpdateUsernameDB(usernameStruct.Username, email.(string))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to UPDATE username to database:", err)
		return
	}

	expMins := 24 * time.Hour

	accessToken, refreshToken, err := utils.GenerateTokens(usernameStruct.Email, expMins)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GENERATE tokens:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+accessToken)

	ctx.SetCookie(
		"refresh_token",
		refreshToken,
		7*24*60*60,
		"/",
		"localhost",
		true,
		true,
	)

	tokenMap := map[string]string{
		"token":        accessToken,
		"refreshToken": refreshToken,
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "username successfully changed"})
	ctx.JSON(http.StatusCreated, gin.H{"data": tokenMap})
}

func ForgotPassword(ctx *gin.Context) {
	var usernameStruct models.Username
	err := ctx.ShouldBindBodyWithJSON(&usernameStruct)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	exUsernameStruct, err := dbhandlers.GetUsernameDB(usernameStruct)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		fmt.Println("Failed to FETCH username data from database:", err)
		return
	}

	code, err := utils.GenerateCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		fmt.Println("Failed to GENERATE 6 digit code:", err)
		return
	}

	err = utils.SendEmail(exUsernameStruct.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SEND 6 digit code to user email:", err)
		return
	}

	var oneTimeCode models.OneTimeCode
	oneTimeCode.Email = exUsernameStruct.Email
	oneTimeCode.Code = code
	oneTimeCode.LastCodeSentAt = time.Now()
	err = dbhandlers.UpdateOneTimeCodeDB(oneTimeCode)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user to database:", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "code sent to your email"})
}

func ConfirmCodeResetPassword(ctx *gin.Context) {

	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	exUser, err := dbhandlers.OneTimeCodeGetUserDB(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	if user.Code != exUser.Code {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "invalid code"})
		return
	}

	tokenString, err := utils.GenTknForChecking(user.Email, "password_only")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GEERATE token:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+tokenString)
	ctx.JSON(http.StatusOK, gin.H{"message": "code successfuly confirmed"})
}

func ResetPassword(ctx *gin.Context) {
	var password models.Password
	err := ctx.ShouldBindBodyWithJSON(&password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	// Verify token
	authHeader := ctx.GetHeader("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte("super_secret_key"), nil
	})

	if err != nil || !token.Valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		fmt.Println("token:", token)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["scope"] != "password_only" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "token not allowed for this action"})
		return
	}
	email := claims["email"]

	// Verify password
	if password.Password != password.RepeatPassword {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "both passwords must be the same"})
		return
	}

	if len(password.Password) < 6 || len(password.Password) > 320 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println("Invalid password!")
		return
	}

	err = utils.CheckString(password.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println(err)
		return
	}

	hashedPassword, err := utils.HashPassword(password.Password)
	password.Password = hashedPassword
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to HASH user password:", err)
		return
	}

	// Save updated password data
	err = dbhandlers.UpdatePasswordDB(password.Password, email.(string))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to UPDATE password in database:", err)
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "password successfully reset"})
}

func LoginWithGoogle(ctx *gin.Context) {

}

func RegisterWithGoogle(ctx *gin.Context) {

}
