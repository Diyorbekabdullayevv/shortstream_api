package models

import "time"

type User struct {
	Id             int       `json:"id"`
	FullName       string    `json:"fullname"`
	Email          string    `json:"email"`
	Password       string    `json:"password"`
	UserCreatedAt  time.Time `json:"user_created_at"`
	LastCodeSentAt time.Time `json:"last_code_sent_at"`
}

type OneTimeCode struct {
	Id             int       `json:"id"`
	Email          string    `json:"email"`
	Code           string    `json:"code"`
	LastCodeSentAt time.Time `json:"last_code_sent_at"`
}

type Username struct {
	ID                int        `json:"id" db:"id"`
	Username          string     `json:"username" db:"username"`
	Email             string     `json:"email" db:"email"`
	UsernameCreatedAt *time.Time `json:"username_created_at,omitempty" db:"username_created_at"`
	UsernameChangedAt *time.Time `json:"username_changed_at,omitempty" db:"username_changed_at"`
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

type Password struct {
	ID                int        `json:"id"`
	Password          string     `json:"password"`
	RepeatPassword    string     `json:"repeat_password,omitempty"`
	Email             string     `json:"email"`
	PasswordCreatedAt *time.Time `json:"password_created_at,omitempty"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
}

type UserInfo struct {
	Email    string
	FullName string
	UID      string
}
