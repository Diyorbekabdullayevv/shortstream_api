package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/database/dbhandlers"
	"virtual_hole_api/internal/models"

	"github.com/gin-gonic/gin"
)

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
