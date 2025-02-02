// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import ( //nolint:gci
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec,gci
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pion/logging"
)

// GenerateLongTermCredentials can be used to create credentials valid for [duration] time
func GenerateLongTermCredentials(sharedSecret string, duration time.Duration) (string, string, error) {
	t := time.Now().Add(duration).Unix()
	username := strconv.FormatInt(t, 10)
	password, err := longTermCredentials(username, sharedSecret)
	return username, password, err
}

// GenerateLongTermTURNRESTCredentials can be used to create credentials valid for [duration] time
func GenerateLongTermTURNRESTCredentials(sharedSecret string, user string, duration time.Duration) (string, string, error) {
	t := time.Now().Add(duration).Unix()
	timestamp := strconv.FormatInt(t, 10)
	username := timestamp + ":" + user
	password, err := longTermCredentials(username, sharedSecret)
	return username, password, err
}

func longTermCredentials(username string, sharedSecret string) (string, error) {
	mac := hmac.New(sha1.New, []byte(sharedSecret))
	_, err := mac.Write([]byte(username))
	if err != nil {
		return "", err // Not sure if this will ever happen
	}
	password := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(password), nil
}

// NewLongTermAuthHandler returns a turn.AuthAuthHandler used with Long Term (or Time Windowed) Credentials.
// See: https://datatracker.ietf.org/doc/html/rfc8489#section-9.2
func NewLongTermAuthHandler(sharedSecret string, l logging.LeveledLogger) AuthHandler {
	if l == nil {
		l = logging.NewDefaultLoggerFactory().NewLogger("turn")
	}
	return func(username, realm string, srcAddr net.Addr) (key []byte, ok bool) {
		l.Tracef("Authentication username=%q realm=%q srcAddr=%v", username, realm, srcAddr)
		t, err := strconv.Atoi(username)
		if err != nil {
			l.Errorf("Invalid time-windowed username %q", username)
			return nil, false
		}
		if int64(t) < time.Now().Unix() {
			l.Errorf("Expired time-windowed username %q", username)
			return nil, false
		}
		password, err := longTermCredentials(username, sharedSecret)
		if err != nil {
			l.Error(err.Error())
			return nil, false
		}
		return GenerateAuthKey(username, realm, password), true
	}
}

// LongTermTURNRESTAuthHandler returns a turn.AuthAuthHandler that can be used to authenticate
// time-windowed ephemeral credentials generated by the TURN REST API as described in
// https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00
//
// The supported format of is timestamp:username, where username is an arbitrary user id and the
// timestamp specifies the expiry of the credential.
func LongTermTURNRESTAuthHandler(sharedSecret string, l logging.LeveledLogger) AuthHandler {
	if l == nil {
		l = logging.NewDefaultLoggerFactory().NewLogger("turn")
	}
	return func(username, realm string, srcAddr net.Addr) (key []byte, ok bool) {
		l.Tracef("Authentication username=%q realm=%q srcAddr=%v\n", username, realm, srcAddr)
		timestamp := strings.Split(username, ":")[0]
		t, err := strconv.Atoi(timestamp)
		if err != nil {
			l.Errorf("Invalid time-windowed username %q", username)
			return nil, false
		}
		if int64(t) < time.Now().Unix() {
			l.Errorf("Expired time-windowed username %q", username)
			return nil, false
		}
		password, err := longTermCredentials(username, sharedSecret)
		if err != nil {
			l.Error(err.Error())
			return nil, false
		}
		return GenerateAuthKey(username, realm, password), true
	}
}
