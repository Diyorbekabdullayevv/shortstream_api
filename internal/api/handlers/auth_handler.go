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
)

// RegisterUser godoc
// @Summary Register a new user
// @Description Create a new user account with email, password, etc.
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.RegisterRequest true "User registration request"
// @Success 201 {object} models.RegisterResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/registration [post]
func RegisterUser(ctx *gin.Context) {

	//* 1 Get user input
	var newUser models.User
	err := ctx.ShouldBindBodyWithJSON(&newUser)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2  Validate user
	if len(newUser.FullName) < 3 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Invalid username!")
		return
	} else if len(newUser.Email) < 4 || !strings.Contains(newUser.Email, "@") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Invalid email!")
		return
	} else if len(newUser.Password) < 6 || len(newUser.Password) > 320 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Invalid password!")
		return
	}

	err = utils.CheckPassword(newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
		fmt.Println(err)
		return
	}

	//* 3  Hash user password
	hashedPassword, err := utils.HashPassword(newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to HASH user password:", err)
		return
	}
	newUser.Password = hashedPassword

	//* 4  Save user data
	err = dbhandlers.SaveUserDB(newUser)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user in the database:", err)
		return
	}

	err = dbhandlers.SavePasswordDB(newUser.Password, newUser.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE password in the database:", err)
		return
	}

	//* 5  Send and save user one_time_code
	code, err := utils.GenerateCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GENERATE 6 digit code:", err)
		return
	}

	err = utils.SendEmail(newUser.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SEND 6 digit code to user email:", err)
		return
	}

	err = dbhandlers.StoreOneTimeCodeDB(newUser, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SEND one time code to database:", err)
		return
	}

	//* 6 Return success response
	// userMap := map[string]any{
	// 	"Name:":  newUser.FullName,
	// 	"Email:": newUser.Email,
	// }

	// ctx.JSON(http.StatusCreated, gin.H{"User:": userMap})
	ctx.JSON(http.StatusOK, gin.H{"message": "Code sent to your email address!"})
}

// LoginUser godoc
// @Summary Login user
// @Description Authenticate user with email and password
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.LoginRequest true "Login request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 401 {object} models.MessageResponse
// @Router /authentication/login [post]
func LoginUser(ctx *gin.Context) {

	//* 1 Get user input
	var user models.User
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Verify user
	userFromDb, err := utils.VerifyUser(user)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println("Failed to VERIFY user:", err)
		return
	}

	//* 3 Generate and manage tokens
	expMins := 15 * time.Minute

	accessToken, refreshToken, err := utils.GenerateTokens(user.Email, expMins)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
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

	//* 4 Save device details
	_, err = utils.SaveUserDetails(ctx, userFromDb)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user details token:", err)
		return
	}

	//* 5 Return success response
	tokenMap := map[string]string{
		"token":        accessToken,
		"refreshToken": refreshToken,
	}
	// ctx.JSON(http.StatusOK, gin.H{"data": tokenMap})
	// ctx.JSON(http.StatusOK, gin.H{"device": device})

	ctx.JSON(http.StatusOK, gin.H{
		"data": tokenMap,
	})
}

// ResendCode godoc
// @Summary Resend verification code
// @Description Resend a one-time verification code to the user's email
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.ForgotPasswordRequest true "Resend code request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/resend_code [put]
func ResendCode(ctx *gin.Context) {

	//* 1 Get user input
	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	if !strings.Contains(user.Email, "@") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid email"})
		return
	}

	//* 2 Get one_time_code data from database
	exUser, err := dbhandlers.OneTimeCodeGetUserDB(user)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	//* 3 Send and save user one_time_code
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

	//* 4 Return success response
	ctx.JSON(http.StatusOK, gin.H{"message": "Code send to your email address!"})
}

// ConfirmCode godoc
// @Summary Confirm verification code
// @Description Confirm the one-time code sent to the user's email
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.CodeConfirmationRequest true "Code confirmation request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/code_confirmation [post]
func ConfirmCode(ctx *gin.Context) {

	//* 1 Get user input
	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Get one_time_code data from database
	exUser, err := dbhandlers.OneTimeCodeGetUserDB(user)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	//* 3 Validate one_time_code
	if user.Code != exUser.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}

	//* 4 Generate token and set as a header
	tokenString, err := utils.GenTknForChecking(user.Email, "username_only")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GEERATE token:", err)
		return
	}
	ctx.Header("Authorization", "Bearer "+tokenString)

	tokenMap := map[string]any{
		"token": tokenString,
	}
	//* 5 Return success response
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Code confirmed successfully!",
		"data":    tokenMap,
	})
}

// CheckUsername godoc
// @Summary Check username availability
// @Description Check if a username is available
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.UsernameRequest true "Username"
// @Success 200 {object} models.UsernameResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 401 {object} models.MessageResponse
// @Router /authentication/check_username [post]
// @Security BearerAuth
func CheckUsername(ctx *gin.Context) {

	var (
		isAvailable        bool
		availableUsernames []string
	)

	//* 1 Get user input
	var usernameStruct models.UsernameRequest
	err := ctx.ShouldBindBodyWithJSON(&usernameStruct)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Validate username
	isValid, err := utils.CheckUsername(usernameStruct.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Invalid username:", err)
		return
	}

	if !isValid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid username"})
		return
	}

	availableUsernames, err = utils.GenerateUsernames(usernameStruct.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GENERATE usernames:", err)
		return
	}

	if len(availableUsernames) > 0 {
		isAvailable = false
	}

	//* 5 Return success response
	ctx.JSON(http.StatusCreated, gin.H{
		"available":           isAvailable,
		"available_usernames": availableUsernames,
	})

}

// ChangeUsername godoc
// @Summary Change username
// @Description Update the user's username
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.UsernameRequest true "Change username request"
// @Success 200 {object} models.UsernameResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 401 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/change_username [post]
// @Security BearerAuth
func ChangeUsername(ctx *gin.Context) {

	//* 1 Get user input
	var usernameStruct models.UsernameRequest
	err := ctx.ShouldBindBodyWithJSON(&usernameStruct)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Validate username
	isValid, err := utils.CheckUsername(usernameStruct.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Invalid username:", err)
		return
	}

	if !isValid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid username"})
		return
	}

	//* 3 Check if user exists
	exists, err := dbhandlers.CheckUsernameIfExistsDB(usernameStruct.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to CHECK if username exists:", err)
		return
	}

	if exists {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "username already choosen by users"})
		return
	}

	//* 4 Update username in the database
	email := ctx.GetString("email_username")
	// err = dbhandlers.UpdateUsernameDB(usernameStruct.Username, email)
	// if err != nil {
	// 	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	// 	fmt.Println("Failed to UPDATE username to database:", err)
	// 	return
	// }

	err = dbhandlers.SaveUsernameDB(usernameStruct.Username, email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE username to database:", err)
		return
	}

	//* 5 Generate and manage tokens
	expMins := 24 * time.Hour
	accessToken, refreshToken, err := utils.GenerateTokens(email, expMins)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GENERATE tokens:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+accessToken)

	tokenMap := map[string]string{
		"token":        accessToken,
		"refreshToken": refreshToken,
	}

	//* 6 Return success response
	ctx.JSON(http.StatusCreated, gin.H{
		"message": "Username successfully changed!",
		"data":    tokenMap,
	})
}

// ForgotPassword godoc
// @Summary Forgot password
// @Description Send a reset code to user's email to reset password
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.ForgotPasswordRequest true "Forgot password request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/forgot_password [put]
func ForgotPassword(ctx *gin.Context) {

	//* 1 Get user input
	var userCred models.ForgotPasswordRequest
	err := ctx.ShouldBindBodyWithJSON(&userCred)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Get username from database
	exUsernameStruct, err := dbhandlers.GetUsernameDB(userCred.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH username data from database:", err)
		return
	}

	//* 3 Send and save user one_time_code
	code, err := utils.GenerateCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GENERATE 6 digit code:", err)
		return
	}

	err = utils.SendEmail(exUsernameStruct.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
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

	//* 4 Return success response
	ctx.JSON(http.StatusOK, gin.H{"message": "Code send to your email address!"})
}

// ConfirmCodeResetPassword godoc
// @Summary Confirm reset code
// @Description Confirm the code sent to reset the user's password
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.CodeConfirmationRequest true "Confirm reset code request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/confirm_code_password [post]
func ConfirmCodeResetPassword(ctx *gin.Context) {

	//* 1 Get user input
	var user models.OneTimeCode
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Get one_time_code data from database
	exUser, err := dbhandlers.OneTimeCodeGetUserDB(user)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to FETCH one_time_code details from database:", err)
		return
	}

	//* 3 Validate one_time_code
	if user.Code != exUser.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}

	//* 4 Generate token and set as a header
	tokenString, err := utils.GenTknForChecking(user.Email, "password_only")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GEERATE token:", err)
		return
	}
	ctx.Header("Authorization", "Bearer "+tokenString)

	tokenMap := map[string]any{
		"token": tokenString,
	}
	//* 5 Return success response
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Code confirmed successfully!",
		"data":    tokenMap,
	})
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset password with email and new password
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.ResetPasswordRequest true "Reset password request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 401 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/reset_password [put]
// @Security BearerAuth
func ResetPassword(ctx *gin.Context) {

	//* 1 Get user input
	var password models.ResetPasswordRequest
	err := ctx.ShouldBindBodyWithJSON(&password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	//* 2 Validate passwords
	if password.NewPassword != password.RepeatPassword {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "repeat password must be identical"})
		return
	}

	if len(password.NewPassword) < 6 || len(password.NewPassword) > 320 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
		fmt.Println("Invalid password!")
		return
	}

	err = utils.CheckPassword(password.NewPassword)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
		fmt.Println(err)
		return
	}

	//* 3 Hash and save updated password
	hashedPassword, err := utils.HashPassword(password.NewPassword)
	password.NewPassword = hashedPassword
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to HASH user password:", err)
		return
	}

	email := ctx.GetString("email_password")
	err = dbhandlers.UpdatePasswordDB(password.NewPassword, email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to UPDATE password in database:", err)
		return
	}

	//* 4 Return success response
	ctx.JSON(http.StatusCreated, gin.H{"message": "Password changed successfully!"})
}

// LoginWithGoogle godoc
// @Summary Login with Google
// @Description Authenticate user using Google account
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.UserInfo true "Google login request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/login_with_google [post]
func LoginWithGoogle(ctx *gin.Context) {

	//* 1 Get user input
	var body struct {
		IDToken string `json:"idToken"`
	}

	if err := ctx.ShouldBindBodyWithJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Bad request:", err)
		return
	}

	//* 2 Verify idToken from google
	userInfo, err := utils.VerifyGoogleIDToken(body.IDToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	//* 3 Check if user exists in the database
	exists, err := dbhandlers.CheckUserIfExistsDB(userInfo.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to CHECK if user exists in the database:", err)
		return
	}

	if !exists {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user with this email doesn`t exists"})
		return
	}

	//* 4 Generate and manage tokens
	expMins := 15 * time.Minute
	accessToken, refreshToken, err := utils.GenerateTokens(userInfo.Email, expMins)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
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

	// tokenMap := map[string]string{
	// 	"token":        accessToken,
	// 	"refreshToken": refreshToken,
	// }

	//* 5 Return success response
	ctx.JSON(http.StatusOK, gin.H{
		"message": "user successfully login. Woo hoo!",
		// "data":    tokenMap,
	})
}

// RegisterWithGoogle godoc
// @Summary Register with Google
// @Description Create a new account using Google account information
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body models.UserInfo true "Google registration request"
// @Success 201 {object} models.RegisterResponse
// @Failure 400 {object} models.MessageResponse
// @Failure 500 {object} models.MessageResponse
// @Router /authentication/register_with_google [post]
func RegisterWithGoogle(ctx *gin.Context) {

	//* 1 Get user input
	var body struct {
		IDToken string `json:"idToken"`
	}

	if err := ctx.ShouldBindBodyWithJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		fmt.Println("Bad request:", err)
		return
	}

	//* 2 Verify idToken from google
	userInfo, err := utils.VerifyGoogleIDToken(body.IDToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	//* 3 Check if user exists in the database
	exists, err := dbhandlers.CheckUserIfExistsDB(userInfo.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to CHECK if user exists in the database:", err)
		return
	}

	if exists {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "user with this email already exists"})
		return
	}

	//* 4 Generate and manage token
	tokenString, err := utils.GenTknForChecking(userInfo.Email, "username_only")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GEERATE token:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+tokenString)

	//* 5 Hash user password
	hashedPassword, err := utils.HashPassword(userInfo.UID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to HASH password:", err)
		return
	}

	//* 6 Save new user to database
	newUser := models.User{
		FullName: userInfo.FullName,
		Email:    userInfo.Email,
		Password: hashedPassword,
	}

	err = dbhandlers.SaveUserDB(newUser)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user to database:", err)
		return
	}

	//* 7 Return success response
	ctx.JSON(http.StatusOK, gin.H{
		"message": "user successfully login",
		// "token":   tokenString,
	})
}
