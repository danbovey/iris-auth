// Package irisauth implements Basic authentication.
package irisauth

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/kataras/iris/context"
	"golang.org/x/crypto/bcrypt"

	"github.com/danbovey/iris-auth/datastore"
)

// See https://godoc.org/golang.org/x/crypto/bcrypt#pkg-constants for more details.
var BcryptCost = 10

// NewSimpleBasic returns *datastore.Simple built from userid, password.
func NewSimpleBasic(userId, hashedPassword string) *datastore.Simple {
	return &datastore.Simple{
		Key:   userId,
		Value: []byte(hashedPassword),
	}
}

// requireAuth writes error to client which initiates the authentication process
// or requires reauthentication.
func requireAuth(ctx context.Context) {
	ctx.Header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
	ctx.StatusCode(401)
	ctx.WriteString("Not Authorized")
}

// getCred get userid, password from request.
func getCred(ctx context.Context) (string, string) {
	// Split authorization header.
	s := strings.SplitN(ctx.GetHeader("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return "", ""
	}

	// Decode credential.
	cred, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", ""
	}

	// Split credential into userid, password.
	pair := strings.SplitN(string(cred), ":", 2)
	if len(pair) != 2 {
		return "", ""
	}

	return pair[0], pair[1]
}

// Basic returns a context.Handler that authenticates via Basic Auth.
// Writes an iris.StatusUnauthorized if authentication fails.
func New(datastore datastore.Datastore) context.Handler {
	return func(ctx context.Context) {
		userId, password := getCred(ctx)

		if userId == "" || password == "" {
			requireAuth(ctx)
			return
		}

		// Extract hashed password from credentials.
		hashedPassword, found := datastore.Get(userId)
		if !found {
			requireAuth(ctx)
			return
		}

		// Check if the password is correct.
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

		// Password not correct. Fail.
		if err != nil {
			requireAuth(ctx)
			return
		}

		// Password correct.
		if ctx.GetStatusCode() != http.StatusUnauthorized {
			ctx.Next()
		}
	}
}
