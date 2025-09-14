package models

import "time"

type RegisterUser struct {
	Id       int    `json:"id"`
	FullName string `json:"fullname"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Device struct {
	UserID     int       `json:"user_id"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	DeviceName string    `json:"device_name"`
	Location   string    `json:"location"`
	LoginAt    time.Time `json:"login_at"`
}

type IpAPIResponse struct {
	Status     string `json:"status"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	Query      string `json:"query"`
}
