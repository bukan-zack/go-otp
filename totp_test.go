package otp_test

import (
	"testing"
	"time"

	"github.com/pixec/go-otp"
)

type totpTestVector struct {
	TimeSec int64
	Code    string
	Hash    otp.Hash
	Secret  []byte
}

var (
	totpSecretSha256 = []byte("12345678901234567890123456789012")
	totpSecretSha512 = []byte("1234567890123456789012345678901234567890123456789012345678901234")

	// Test vectors were taken from https://www.rfc-editor.org/rfc/rfc6238#appendix-B
	totpTestVectors = []totpTestVector{
		{59, "46119246", otp.HashSHA256, totpSecretSha256},
		{59, "90693936", otp.HashSHA512, totpSecretSha512},
		{1111111109, "68084774", otp.HashSHA256, totpSecretSha256},
		{1111111109, "25091201", otp.HashSHA512, totpSecretSha512},
		{1111111111, "67062674", otp.HashSHA256, totpSecretSha256},
		{1111111111, "99943326", otp.HashSHA512, totpSecretSha512},
		{1234567890, "91819424", otp.HashSHA256, totpSecretSha256},
		{1234567890, "93441116", otp.HashSHA512, totpSecretSha512},
		{2000000000, "90698825", otp.HashSHA256, totpSecretSha256},
		{2000000000, "38618901", otp.HashSHA512, totpSecretSha512},
		{20000000000, "77737706", otp.HashSHA256, totpSecretSha256},
		{20000000000, "47863826", otp.HashSHA512, totpSecretSha512},
	}
)

func TestTOTPGenerate(t *testing.T) {
	totp, _ := otp.NewTOTP(otp.TOTPOptions{
		TimeStart: time.Unix(0, 0),
		Digits:    otp.DigitsEight,
	})

	for _, tv := range totpTestVectors {
		totp.SetSecret(tv.Secret)
		totp.SetTime(time.Unix(tv.TimeSec, 0).UTC())
		totp.SetHash(tv.Hash)

		code, err := totp.Generate()
		if err != nil {
			t.Error(err)
		}

		if code != tv.Code {
			t.Errorf("expected %s, got %s", tv.Code, code)
		}
	}
}

func TestTOTPValidate(t *testing.T) {
	totp, _ := otp.NewTOTP(otp.TOTPOptions{
		TimeStart: time.Unix(0, 0),
		Digits:    otp.DigitsEight,
	})

	for _, tv := range totpTestVectors {
		totp.SetSecret(tv.Secret)
		totp.SetTime(time.Unix(tv.TimeSec, 0).UTC())
		totp.SetHash(tv.Hash)

		if err := totp.Validate(tv.Code); err != nil {
			t.Error(err)
		}
	}
}
