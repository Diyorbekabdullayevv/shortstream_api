package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"virtual_hole_api/internal/database/dbhandlers"
	"virtual_hole_api/internal/moduls"
	"virtual_hole_api/utils"

	"github.com/gin-gonic/gin"
)

func RegisterUser(ctx *gin.Context) {
	var newUser moduls.RegisterUser
	err := ctx.ShouldBindBodyWithJSON(&newUser)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "error"})
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

	userMap := map[string]any{
		"Name:":  newUser.FullName,
		"Email:": newUser.Email,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully registered"})
	ctx.JSON(http.StatusCreated, gin.H{"User:": userMap})
}

func GetUser(ctx *gin.Context) {
	userId := ctx.Param("id")

	user, err := dbhandlers.GetUserDB(ctx, userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to GET user from database:", err)
		return
	}

	userMap := map[string]any{
		"Name:":  user.FullName,
		"Email:": user.Email,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "success"})
	ctx.JSON(http.StatusFound, gin.H{"User:": userMap})
}
