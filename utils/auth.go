package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"time"
	"unicode"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/database/dbhandlers"
	"virtual_hole_api/internal/models"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
)

const charset = "abcdefghijklmnopqrstuvwxyz0123456789._"

func VerifyUser(user models.User) (models.User, error) {

	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.User{}, err
	}
	defer db.Close()

	var existingUser models.User
	err = db.QueryRow(`SELECT id, email, password FROM users where email = $1`, user.Email).
		Scan(&existingUser.Id, &existingUser.Email, &existingUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, err
		}
		return models.User{}, err
	}

	if user.Email != existingUser.Email {
		return models.User{}, errors.New("invalid email")
	}

	isValid := CheckHashPassword(user.Password, existingUser.Password)
	if !isValid {
		return models.User{}, errors.New("invalid password")
	}

	return existingUser, nil
}

func SaveUserDetails(ctx *gin.Context, user models.User) (models.Device, error) {
	var (
		country string
		region  string
		city    string
	)
	id := user.Id
	ipAdr := ctx.ClientIP()
	userAgent := ctx.GetHeader("User-Agent")
	deviceName := "unknown"
	location, err := lookupIPLocation(ipAdr)
	if err == nil {
		country, region, city = location.Country, location.RegionName, location.City
	} else {
		country, region, city = "unknown", "unknown", "unknown"
	}

	loginAt := time.Now().UTC()

	device := models.Device{
		UserID:     id,
		IP:         ipAdr,
		UserAgent:  userAgent,
		DeviceName: deviceName,
		Location:   country + " ," + region + " ," + city,
		LoginAt:    loginAt,
	}
	db, err := dbConnect.ConnectDB()
	if err != nil {
		return models.Device{}, err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO devices (user_id, ip, user_agent, device_name, location, login_at) VALUES ($1,$2,$3, $4, $5, $6)`,
		device.UserID, device.IP, device.UserAgent, device.DeviceName, device.Location, device.LoginAt)
	if err != nil {
		return models.Device{}, err
	}
	return device, nil
}

func lookupIPLocation(ip string) (*models.IpAPIResponse, error) {
	client := http.Client{Timeout: 2 * time.Second}
	url := "http://ip-api.com/json/" + ip
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response models.IpAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, fmt.Errorf("lookup failed")
	}
	return &response, nil
}

func CanSendCode(lastSent time.Time) (bool, int) {
	now := time.Now()

	if lastSent.IsZero() {
		return true, 0
	}

	elapsed := now.Sub(lastSent)

	if elapsed >= 3*time.Minute {
		return true, 0
	}

	remaining := int((3*time.Minute - elapsed).Seconds())

	return false, remaining
}

func CheckPassword(str string) error {

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

func VerifyGoogleIDToken(idToken string) (models.UserInfo, error) {

	// Replace with your Google Client ID
	clientID := os.Getenv("CLIENT_ID")

	payload, err := idtoken.Validate(context.Background(), idToken, clientID)
	if err != nil {
		return models.UserInfo{}, fmt.Errorf("invalid ID token: %v", err)
	}

	claims := payload.Claims

	// Extract email
	email, ok := claims["email"].(string)
	if !ok {
		return models.UserInfo{}, fmt.Errorf("email not found in token")
	}

	// Extract full name (if available)
	fullName, _ := claims["name"].(string) // not always present, safe cast

	// Extract Google UID (the 'sub' claim is always present)
	uid, ok := claims["sub"].(string)
	if !ok {
		return models.UserInfo{}, fmt.Errorf("uid not found in token")
	}

	return models.UserInfo{
		Email:    email,
		FullName: fullName,
		UID:      uid,
	}, nil
}

func CheckUsername(s string) (bool, error) {
	match, err := regexp.MatchString(`^[a-z0-9._]{3,56}$`, s)
	if err != nil {
		return false, err
	}
	return match, nil
}

func randomUsername(base string, totalLen int) string {
	rand.Seed(time.Now().UnixNano())

	if len(base) > totalLen {
		totalLen = len(base) + 5
	}

	randomPart := make([]byte, totalLen-len(base))
	for i := range randomPart {
		randomPart[i] = charset[rand.Intn(len(charset))]
	}

	pos := rand.Intn(totalLen - len(base) + 1)
	return string(randomPart[:pos]) + base + string(randomPart[pos:])
}

func GenerateUsernames(username string) ([]string, error) {

	_, err := dbhandlers.GetUsernameDB(username)
	if err == nil {
		// username already exists, so we need to suggest new ones
	} else {
		// not found → return empty (means it's available)
		return nil, nil
	}

	var suggestions []string
	tries := 0

	for len(suggestions) < 5 && tries < 100 {
		tries++
		candidate := randomUsername(username, rand.Intn(12-5+1)+5) // length 5–12

		// check if candidate exists in DB
		_, err := dbhandlers.GetUsernameDB(candidate)
		if err != nil { // not found → available
			suggestions = append(suggestions, candidate)
		}
	}

	if len(suggestions) == 0 {
		return nil, fmt.Errorf("could not generate available usernames")
	}

	return suggestions, nil
}
