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
	Password          string     `json:"new_password"`
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

// RegisterRequest represents user registration input
type RegisterRequest struct {
	FullName string `json:"fullname" example:"John Doe"`
	Email    string `json:"email" example:"john@example.com"`
	Password string `json:"password" example:"Secret123!"`
}

// LoginRequest represents login input
type LoginRequest struct {
	Email    string `json:"email" example:"john@example.com"`
	Password string `json:"password" example:"Secret123!"`
}

// CodeConfirmationRequest represents code confirmation input
type CodeConfirmationRequest struct {
	Email string `json:"email" example:"john@example.com"`
	Code  string `json:"code" example:"123456"`
}

// UsernameRequest for checking/changing username
type UsernameRequest struct {
	Username string `json:"username" example:"johndoe"`
}

// ForgotPasswordRequest for initiating reset
type ForgotPasswordRequest struct {
	Email string `json:"email" example:"john@example.com"`
}

// ResetPasswordRequest for resetting password
type ResetPasswordRequest struct {
	NewPassword    string `json:"new_password" example:"NewSecret123!"`
	RepeatPassword string `json:"repeat_password" example:"NewSecret123!"`
}

// ---------------------- Responses ----------------------

// RegisterResponse after successful registration
type RegisterResponse struct {
	Message string `json:"message" example:"Code sent to your email address!"`
}

// LoginResponse after successful login
type LoginResponse struct {
	Token     string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	ExpiresIn int64  `json:"expires_in" example:"3600"`
}

// UsernameResponse after checking/changing username
type UsernameResponse struct {
	Username string `json:"username" example:"johndoe"`
	Status   string `json:"status" example:"available"`
}

// MessageResponse is a generic message container
type MessageResponse struct {
	Message string `json:"message" example:"Operation successful"`
}
