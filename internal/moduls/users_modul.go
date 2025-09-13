package moduls

type RegisterUser struct {
	FullName string `json:"fullname"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
