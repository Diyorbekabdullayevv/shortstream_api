package dbhandlers

import (
	"errors"
	"time"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/models"
)

func SaveUserDB(newUser models.User) error {
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

func CheckUserIfExistsDB(email string) (bool, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return false, err
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow(`SELECT EXISTS (SELECT 1 FROM users where email = $1)`, email).
		Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
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

func OneTimeCodeGetUserDB(oneTimeCode models.OneTimeCode) (models.OneTimeCode, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.OneTimeCode{}, err
	}
	defer db.Close()

	var newCode models.OneTimeCode
	err = db.QueryRow(`SELECT email, code, last_code_sent_at FROM one_time_code WHERE email = $1`, oneTimeCode.Email).Scan(&newCode.Email, &newCode.Code, &newCode.LastCodeSentAt)
	if err != nil {
		return models.OneTimeCode{}, err
	}
	return newCode, nil
}

func UpdateOneTimeCodeDB(user models.OneTimeCode) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE one_time_code SET code = $1, last_code_sent_at = $2 WHERE email = $3`, user.Code, user.LastCodeSentAt, user.Email)
	if err != nil {
		return err
	}
	return nil
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

func UpdateUsernameDB(username, email string) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE usernames SET username = $1, username_changed_at = $2 WHERE email = $3`, username, time.Now().UTC(), email)
	if err != nil {
		return err
	}
	return nil
}

func GetUsernameDB(usernameStruct models.Username) (models.Username, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.Username{}, err
	}
	defer db.Close()

	var exUsernameStruct models.Username
	if usernameStruct.Username != "" {
		err = db.QueryRow(`SELECT * FROM usernames WHERE username = $1`, usernameStruct.Username).
			Scan(&exUsernameStruct.ID, &exUsernameStruct.Username, &exUsernameStruct.Email, &exUsernameStruct.UsernameCreatedAt, &exUsernameStruct.UsernameChangedAt)
		if err != nil {
			return models.Username{}, err
		}
	} else if usernameStruct.Email != "" {
		err = db.QueryRow(`SELECT * FROM usernames WHERE email = $1`, usernameStruct.Email).
			Scan(&exUsernameStruct.ID, &exUsernameStruct.Username, &exUsernameStruct.Email, &exUsernameStruct.UsernameCreatedAt, &exUsernameStruct.UsernameChangedAt)
		if err != nil {
			return models.Username{}, err
		}
	} else {
		return models.Username{}, errors.New("either username or email must be provided")
	}

	return exUsernameStruct, nil
}

func SavePasswordDB(password, email string) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO passwords (password, email) VALUES ($1, $2)`, password, email)
	if err != nil {
		return err
	}
	return nil
}

func UpdatePasswordDB(password, email string) error {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE passwords SET password = $1, password_changed_at = $2 WHERE email = $3`, password, time.Now().UTC(), email)
	if err != nil {
		return err
	}
	return nil
}

func GetPasswordDB(email string) (models.Password, error) {
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.Password{}, err
	}
	defer db.Close()

	var password models.Password
	err = db.QueryRow(`SELECT * FROM passwords email = $1`, email).
		Scan(&password.ID, &password.Password, &password.Email, &password.PasswordCreatedAt, &password.PasswordChangedAt)
	if err != nil {
		return models.Password{}, err
	}
	return password, nil
}
