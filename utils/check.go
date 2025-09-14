package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"unicode"
	"virtual_hole_api/internal/moduls"

	"github.com/gin-gonic/gin"
)

var (
	jsonFileName = "registered_users.json"
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

func StoreDataToJsonFile(ctx *gin.Context, newUser moduls.RegisterUser) error {
	var users []moduls.RegisterUser
	jsonData, err := os.ReadFile(jsonFileName)
	if err == nil && len(jsonData) > 0 {
		err := json.Unmarshal(jsonData, &users)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			fmt.Println("Failed to UNMARSHAL data from JSON format:", err)
			return err
		}
	}

	if len(users) == 0 {
		users = append(users, newUser)
	} else {
		for _, user := range users {
			if user.Email == newUser.Email {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "user with this email already exists"})
				return err
			}
		}
		users = append(users, newUser)
	}

	bytes, err := json.MarshalIndent(users, "", " ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to MARSHAL user data to JSON format:", err)
		return err
	}

	err = os.WriteFile(jsonFileName, bytes, 0644)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to WRITE data to JSON file:", err)
		return err
	}
	return nil
}

// err = utils.StoreDataToJsonFile(ctx, newUser)
// if err != nil {
// 	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 	fmt.Println("Failed to STORE data to JSON file!")
// 	return
// }
// db, err := db.ConnectDB()
// if err != nil {
// 	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 	fmt.Println("Failed to CONNECT to database:", err)
// 	return
// }
// defer db.Close()

// _, err = db.Exec(`INSERT INTO UserRegistration (fullname, email, password) VALUES (?,?,?)`, newUser.FullName, newUser.Email, newUser.Password)
// if err != nil {
// 	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
// 	fmt.Println("Failed to EXECUTE data to database:", err)
// 	return
// }
