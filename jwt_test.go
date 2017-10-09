package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/yohgo/middleware"
)

// jwtAuthenticateDataProvider provides data for the TestJWTAuthenticate function.
var jwtAuthenticateDataProvider = []struct {
	name    string
	options middleware.Options
	claims  jwt.MapClaims
	method  jwt.SigningMethod
	token   string
	want    bool
}{
	{
		name: "A successful JWT authentication",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() + 86400),
			"iat": time.Now().Unix(),
			"nbf": time.Now().Unix(),
		},
		method: jwt.SigningMethodHS256,
		token:  "",
		want:   true,
	},
	{
		name: "A failed JWT authentication with expired token",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() - 86400),
			"iat": time.Now().Unix(),
			"nbf": time.Now().Unix(),
		},
		method: jwt.SigningMethodHS256,
		token:  "",
		want:   false,
	},
	{
		name: "A failed JWT authentication with used before date allowed",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() + 86400),
			"iat": time.Now().Unix(),
			"nbf": (time.Now().Unix() + 43200),
		},
		method: jwt.SigningMethodHS256,
		token:  "",
		want:   false,
	},
	{
		name: "A failed JWT authentication with token issued in the future",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() + 86400),
			"iat": (time.Now().Unix() + 43200),
			"nbf": time.Now().Unix(),
		},
		method: jwt.SigningMethodHS256,
		token:  "",
		want:   false,
	},
	{
		name: "A failed JWT authentication with invalid token",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() + 86400),
			"iat": (time.Now().Unix() + 43200),
			"nbf": time.Now().Unix(),
		},
		method: jwt.SigningMethodHS256,
		token:  "ThiSISan1inVAlidTOKen",
		want:   false,
	},
	{
		name: "A failed JWT authentication with invalid signing method",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		claims: jwt.MapClaims{
			"exp": (time.Now().Unix() + 86400),
			"iat": time.Now().Unix(),
			"nbf": time.Now().Unix(),
		},
		method: jwt.SigningMethodES384,
		token:  "",
		want:   false,
	},
}

// TestJWTAuthenticate tests the JWTAuthenticate method.
func TestJWTAuthenticate(t *testing.T) {
	t.Log("JWTAuthenticate")
	// Check each test case
	for _, testcase := range jwtAuthenticateDataProvider {
		t.Log(testcase.name)

		// Create JWT token
		token := testcase.token
		if token == "" {
			token, _ = jwt.NewWithClaims(
				testcase.method,
				testcase.claims,
			).SignedString([]byte(testcase.options.JWTKey))
		}

		recorder := httptest.NewRecorder()
		request, _ := http.NewRequest(http.MethodGet, "/users", nil)
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		mid := middleware.New(testcase.options)

		got := mid.JWTAuthenticate(recorder, request)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("JWTAuthenticate() = %v, want %v", got, testcase.want)
		}
	}
}
