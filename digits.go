package otp

import "strconv"

type Digits uint8

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

func (d Digits) Int() int {
	return int(d)
}

func (d Digits) String() string {
	return strconv.Itoa(d.Int())
}
