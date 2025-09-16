package dbhandlers

import (
	"database/sql"
	"net/http"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/models"

	"github.com/gin-gonic/gin"
)

func RegisterUserDB(newUser models.User) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO users (fullname, email, password) VALUES ($1,$2,$3)`, newUser.FullName, newUser.Email, newUser.Password)
	if err != nil {
		return err
	}
	return nil
}

func StoreOneTimeCodeDB(user models.User, code string) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO one_time_code (email, code) VALUES ($1, $2)`, user.Email, code)
	if err != nil {
		return err
	}
	return nil
}

func OneTimeCodeGetUserDB(ctx *gin.Context, oneTimeCode models.OneTimeCode) (models.OneTimeCode, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.OneTimeCode{}, err
	}
	defer db.Close()

	var newCode models.OneTimeCode
	err = db.QueryRow(`SELECT email, code, last_code_sent_at FROM one_time_code WHERE email = $1`, oneTimeCode.Email).Scan(&newCode.Email, &newCode.Code, &newCode.LastCodeSentAt)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return models.OneTimeCode{}, err
		}
		return models.OneTimeCode{}, err
	}
	return newCode, nil
}

func ResendCodeStoreUserDB(user models.OneTimeCode) (models.OneTimeCode, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.OneTimeCode{}, err
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE one_time_code SET code = $1, last_code_sent_at = $2 WHERE email = $3`, user.Code, user.LastCodeSentAt, user.Email)
	if err != nil {
		return models.OneTimeCode{}, err
	}
	return user, nil
}

func GetUserDB(ctx *gin.Context, userId string) (models.User, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.User{}, err
	}
	defer db.Close()

	var user models.User
	err = db.QueryRow(`SELECT fullname, email, password FROM users where id = $1`, userId).
		Scan(&user.FullName, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		}
		return models.User{}, err
	}
	return user, nil
}

func CheckUsernameIfExistsDB(username string) (bool, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return false, err
	}
	defer db.Close()
	var exists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM usernames WHERE username = $1)`, username).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func SaveUsernameDB(username, email string) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO usernames (username, email) VALUES ($1, $2)`, username, email)
	if err != nil {
		return err
	}
	return nil
}
