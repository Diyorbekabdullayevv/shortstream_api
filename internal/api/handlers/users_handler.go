package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"virtual_hole_api/internal/moduls"
	"virtual_hole_api/utils"

	"github.com/gin-gonic/gin"
)

var (
	jsonFileName = "registered_users.json"
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
	}

	if len(newUser.Password) < 6 || len(newUser.Password) > 320 {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println("Invalid password!")
		return
	}

	err = utils.CheckString(newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		fmt.Println(err)
		fmt.Println(newUser.Password)
		return
	}

	var users []moduls.RegisterUser
	jsonData, err := os.ReadFile(jsonFileName)
	if err == nil && len(jsonData) > 0 {
		err := json.Unmarshal(jsonData, &users)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			fmt.Println("Failed to UNMARSHAL data from JSON format:", err)
			return
		}
	}

	if len(users) == 0 {
		users = append(users, newUser)
	} else {
		for _, user := range users {
			if user.Email == newUser.Email {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "user with this email already exists"})
				return
			}
		}
		users = append(users, newUser)
	}

	bytes, err := json.MarshalIndent(users, "", " ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to MARSHAL user data to JSON format:", err)
		return
	}

	err = os.WriteFile(jsonFileName, bytes, 0644)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		fmt.Println("Failed to WRITE data to JSON file:", err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully registered"})
}
