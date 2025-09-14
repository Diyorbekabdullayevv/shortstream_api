package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"virtual_hole_api/internal/database/dbConnect"
	"virtual_hole_api/internal/database/dbhandlers"
	"virtual_hole_api/internal/models"
	"virtual_hole_api/utils"

	"github.com/gin-gonic/gin"
)

func RegisterUser(ctx *gin.Context) {
	var newUser models.RegisterUser
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

	code, err := utils.GenerateCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to GENERATE 6 digit code:", err)
		return
	}

	err = utils.SendEmail(newUser.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "internal server error"})
		fmt.Println("Failed to SEND 6 digit code to user email:", err)
		return
	}

	userMap := map[string]any{
		"Name:":  newUser.FullName,
		"Email:": newUser.Email,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully registered"})
	ctx.JSON(http.StatusCreated, gin.H{"User:": userMap})
}

func Login(ctx *gin.Context) {

	var user models.RegisterUser
	err := ctx.ShouldBindBodyWithJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "error"})
		fmt.Println("Failed to BIND body with json:", err)
		return
	}

	userFromDb, err := utils.VerifyUser(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println("Failed to VERIFY user:", err)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println("Failed to GENERATE token:", err)
		return
	}

	ctx.Header("Authorization", "Bearer "+accessToken)

	ctx.SetCookie(
		"refresh_token",
		refreshToken, // your JWT or UUID string
		7*24*60*60,   // expiry in seconds (7 days here)
		"/",          // path
		"localhost",  // domain (use your domain in prod)
		true,         // secure (true = only HTTPS)
		true,         // httpOnly (client-side JS can't access)
	)

	device, err := SaveUserDetails(ctx, userFromDb)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		fmt.Println("Failed to SAVE user details token:", err)
		return
	}

	tokenMap := map[string]string{
		"token":        accessToken,
		"refreshToken": refreshToken,
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "user successfully login!"})
	ctx.JSON(http.StatusOK, gin.H{"data": tokenMap})
	ctx.JSON(http.StatusOK, gin.H{"device": device})
}

func SaveUserDetails(ctx *gin.Context, user models.RegisterUser) (models.Device, error) {
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

	var r models.IpAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("lookup failed")
	}
	return &r, nil
}
