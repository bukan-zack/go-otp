package otp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"math"
	"net/url"
	"time"
)

type TOTP struct {
	secret    []byte
	time      time.Time
	timeStart time.Time
	digits    Digits
	period    uint64
	hash      Hash
}

type TOTPOptions struct {
	Secret    []byte    // Secret between client and server. K in RFC 4226.
	Time      time.Time // Current time in RFC 6238.
	TimeStart time.Time // Time to start counting time steps. T0 in RFC 6238.
	Digits    Digits    // Number of digits in a TOTP code. Digit in RFC 4226.
	Period    uint64    // Time step in seconds, X in RFC 6238, 30 seconds is recommended.
	Hash      Hash      // Algorithm for the TOTP, SHA256 is recommended.
}

// NewTOTP returns a new TOTP.
func NewTOTP(opts TOTPOptions) (*TOTP, error) {
	t := &TOTP{
		secret:    opts.Secret,
		time:      opts.Time,
		timeStart: opts.TimeStart,
		digits:    opts.Digits,
		period:    opts.Period,
		hash:      opts.Hash,
	}

	if t.secret == nil {
		t.secret = make([]byte, t.hash.Size())
		if _, err := rand.Read(t.secret); err != nil {
			return nil, err
		}
	}

	if t.period == 0 {
		// The recommended time step is 30 seconds.
		// See https://www.rfc-editor.org/rfc/rfc6238#section-5.2
		t.period = 30
	}

	return t, nil
}

// SetSecret sets the secret for the TOTP.
func (t *TOTP) SetSecret(secret []byte) {
	t.secret = secret
}

// Secret returns the TOTP secret.
func (t *TOTP) Secret() []byte {
	return t.secret
}

// Base32Secret returns the TOTP secret encoded in base32.
func (t *TOTP) Base32Secret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.secret)
}

// SetTime sets the TOTP time.
func (t *TOTP) SetTime(tm time.Time) {
	t.time = tm
}

// Time returns the TOTP time.
func (t *TOTP) Time() time.Time {
	return t.time
}

// SetTimeStart sets the TOTP time start.
func (t *TOTP) SetTimeStart(tm time.Time) {
	t.timeStart = tm
}

// Time returns the TOTP time start.
func (t *TOTP) TimeStart() time.Time {
	return t.timeStart
}

// SetDigits sets the TOTP digits.
func (t *TOTP) SetDigits(digits Digits) {
	t.digits = digits
}

// Digits returns the TOTP digits.
func (t *TOTP) Digits() Digits {
	return t.digits
}

// SetDigits sets the TOTP period.
func (t *TOTP) SetPeriod(period uint64) {
	t.period = period
}

// Digits returns the TOTP digits.
func (t *TOTP) Period() uint64 {
	return t.period
}

// SetHash sets the hash algorithm for the TOTP.
func (t *TOTP) SetHash(hash Hash) {
	t.hash = hash
}

// Hash returns the TOTP hash algorithm.
func (t *TOTP) Hash() Hash {
	return t.hash
}

// URL returns [net/url.URL] representation for the TOTP.
func (t *TOTP) URL(issuer, accountName string) *url.URL {
	query := url.Values{}
	query.Add("secret", t.Base32Secret())
	query.Add("issuer", issuer)
	query.Add("algorithm", t.hash.String())
	query.Add("digits", t.digits.String())

	return &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     fmt.Sprintf("/%s:%s", issuer, accountName),
		RawQuery: query.Encode(),
	}
}

// Generate returns cryptographically generated TOTP code.
func (t *TOTP) Generate() (string, error) {
	// T = (Current Unix time - T0) / X
	counter := uint64(math.Floor(float64(t.time.Unix()-t.timeStart.Unix()) / float64(t.period)))

	hotp, err := NewHOTP(HOTPOptions{
		Secret:  t.secret,
		Counter: counter,
		Digits:  t.digits,
		Hash:    t.hash,
	})
	if err != nil {
		return "", err
	}

	return hotp.Generate()
}

// Validate validates given TOTP code.
func (t *TOTP) Validate(code string) error {
	if len(code) != t.digits.Int() {
		return ErrInvalidCode
	}

	genCode, err := t.Generate()
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(genCode)) == 0 {
		return ErrInvalidCode
	}

	return nil
}
