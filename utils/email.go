package utils

import (
	"crypto/rand"
	"math/big"

	"gopkg.in/gomail.v2"
)

func SendEmail(to string, code string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", "diyorbekabdullayevv2003@gmail.com")
	// message.SetHeader("Diyor akangdan xabar keldi!")
	message.SetHeader("To", to)
	message.SetHeader("Subject", "Your Verification Code")
	message.SetBody("text/plain", "Your verification code is: "+code)

	dialer := gomail.NewDialer("smtp.gmail.com", 587, "diyorbekabdullayevv2003@gmail.com", "rumw ocxo ercj duqx")

	return dialer.DialAndSend(message)
}

func GenerateCode() (string, error) {
	code := ""
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code += n.String()
	}
	return code, nil
}
