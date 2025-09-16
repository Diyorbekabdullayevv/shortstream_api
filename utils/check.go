package utils

import (
	"errors"
	"fmt"
	"net/http"
	"unicode"
	"virtual_hole_api/internal/database/dbhandlers"

	"github.com/gin-gonic/gin"
)

func CheckString(str string) error {

	var (
		upperLenth  []any
		lowerLenth  []any
		symbolLenth []any
		digitLenth  []any
	)
	for _, r := range str {
		switch {
		case unicode.IsUpper(r):
			upperLenth = append(upperLenth, r)
		case unicode.IsLower(r):
			lowerLenth = append(lowerLenth, r)
		case unicode.IsSymbol(r), unicode.IsPunct(r):
			symbolLenth = append(symbolLenth, r)
		case unicode.IsDigit(r):
			digitLenth = append(digitLenth, r)
		}
	}

	if len(upperLenth) < 2 || len(lowerLenth) < 2 || len(symbolLenth) < 1 || len(digitLenth) < 1 {
		return errors.New("error: invalid password")
	}

	return nil
}

// func StoreDataToJsonFile(ctx *gin.Context, newUser models.RegisterUser) error {
// 	var users []models.RegisterUser
// 	jsonData, err := os.ReadFile(jsonFileName)
// 	if err == nil && len(jsonData) > 0 {
// 		err := json.Unmarshal(jsonData, &users)
// 		if err != nil {
// 			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 			fmt.Println("Failed to UNMARSHAL data from JSON format:", err)
// 			return err
// 		}
// 	}

// 	if len(users) == 0 {
// 		users = append(users, newUser)
// 	} else {
// 		for _, user := range users {
// 			if user.Email == newUser.Email {
// 				ctx.JSON(http.StatusBadRequest, gin.H{"error": "user with this email already exists"})
// 				return err
// 			}
// 		}
// 		users = append(users, newUser)
// 	}

// 	bytes, err := json.MarshalIndent(users, "", " ")
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 		fmt.Println("Failed to MARSHAL user data to JSON format:", err)
// 		return err
// 	}

// 	err = os.WriteFile(jsonFileName, bytes, 0644)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 		fmt.Println("Failed to WRITE data to JSON file:", err)
// 		return err
// 	}
// 	return nil
// }

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
