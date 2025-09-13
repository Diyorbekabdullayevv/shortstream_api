package utils

import (
	"errors"
	"fmt"
	"unicode"
)

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
		case unicode.IsSymbol(r), unicode.IsPunct(r) :
			symbolLenth = append(symbolLenth, r)
		case unicode.IsDigit(r):
			digitLenth = append(digitLenth, r)
		}
	}

	// fmt.Printf("Upper: %v\nLower: %v\nDigit: %v\nSymbol: %v\n", len(upperLenth), len(lowerLenth), len(digitLenth), len(symbolLenth))

	if len(upperLenth) < 2 || len(lowerLenth) < 2 || len(symbolLenth) < 1 || len(digitLenth) < 1 {
		fmt.Println("Password must contain 2 uppercase, 2 lowercase letters, 1 digit and 1 symbol!")
		return errors.New("error: invalid password")
	}

	return nil
}
