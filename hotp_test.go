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
	for _, tv := range hotpTestVectors {
		code, err := otp.NewCustomHOTP(otp.HOTPOptions{
			Secret:  hotpSecret,
			Counter: tv.Count,
			Hash:    otp.HashSHA1,
			Digits:  otp.DigitsSix,
		}).Generate()
		if err != nil {
			t.Error(err)
		}

		if code != tv.Code {
			t.Errorf("expected %s, got %s", tv.Code, code)
		}
	}
}

func TestHOTPValidate(t *testing.T) {
	for _, tv := range hotpTestVectors {
		if err := otp.NewCustomHOTP(otp.HOTPOptions{
			Secret:  hotpSecret,
			Counter: tv.Count,
			Hash:    otp.HashSHA1,
			Digits:  otp.DigitsSix,
		}).Validate(tv.Code); err != nil {
			t.Error(err)
		}
	}
}
