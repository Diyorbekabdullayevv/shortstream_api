package dbhandlers

import (
	"database/sql"
	"net/http"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/models"

	"github.com/gin-gonic/gin"
)

func RegisterUserDB(newUser models.RegisterUser) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO RegisterUser (fullname, email, password) VALUES ($1,$2,$3)`, newUser.FullName, newUser.Email, newUser.Password)
	if err != nil {
		return err
	}
	return nil
}

func GetUserDB(ctx *gin.Context, userId string) (models.RegisterUser, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.RegisterUser{}, err
	}
	defer db.Close()

	var user models.RegisterUser
	err = db.QueryRow(`SELECT fullname, email, password FROM RegisterUser where id = $1`, userId).
		Scan(&user.FullName, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		}
		return models.RegisterUser{}, err
	}
	return user, nil
}
