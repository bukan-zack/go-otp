package otp_test

import (
	"testing"

	"github.com/pixec/go-otp"
)

type hotpTestVector struct {
	Count uint64
	Code  string
}

var (
	hotpSecret = []byte("12345678901234567890")

	// Test vectors were taken from https://www.rfc-editor.org/rfc/rfc4226#appendix-D
	hotpTestVectors = []hotpTestVector{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}
)

func TestHOTPGenerate(t *testing.T) {
	hotp, _ := otp.NewHOTP(otp.HOTPOptions{
		Secret: hotpSecret,
		Digits: otp.DigitsSix,
		Hash:   otp.HashSHA1,
	})

	for _, tv := range hotpTestVectors {
		hotp.SetCounter(tv.Count)

		code, err := hotp.Generate()
		if err != nil {
			t.Error(err)
		}

		if code != tv.Code {
			t.Errorf("expected %s, got %s", tv.Code, code)
		}
	}
}

func TestHOTPValidate(t *testing.T) {
	hotp, _ := otp.NewHOTP(otp.HOTPOptions{
		Secret: hotpSecret,
		Digits: otp.DigitsSix,
		Hash:   otp.HashSHA1,
	})

	for _, tv := range hotpTestVectors {
		hotp.SetCounter(tv.Count)

		if err := hotp.Validate(tv.Code); err != nil {
			t.Error(err)
		}
	}
}
