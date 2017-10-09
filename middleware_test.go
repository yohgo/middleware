package middleware_test

import (
	"reflect"
	"testing"

	"github.com/yohgo/middleware"
)

// newDataProvider provides data for the TestNew function.
var newDataProvider = []struct {
	name    string
	options middleware.Options
	want    *middleware.Middleware
}{
	{
		name: "Create Middleware with complete options",
		options: middleware.Options{
			JWTKey:        []byte("secret"),
			JWTContextKey: "token",
		},
		want: &middleware.Middleware{
			Options: middleware.Options{
				JWTKey:        []byte("secret"),
				JWTContextKey: "token",
			},
		},
	},
	{
		name: "Create Middleware with missing JWTKey options",
		options: middleware.Options{
			JWTContextKey: "token",
		},
		want: &middleware.Middleware{
			Options: middleware.Options{
				JWTKey:        nil,
				JWTContextKey: "token",
			},
		},
	},
	{
		name: "Create Middleware with missing JWTContextKey options",
		options: middleware.Options{
			JWTKey: []byte("secret"),
		},
		want: &middleware.Middleware{
			Options: middleware.Options{
				JWTKey:        []byte("secret"),
				JWTContextKey: "",
			},
		},
	},
	{
		name:    "Create Middleware with empty options",
		options: middleware.Options{},
		want: &middleware.Middleware{
			Options: middleware.Options{},
		},
	},
}

// TestNew tests the middleware New method.
func TestNew(t *testing.T) {
	t.Log("New")
	// Check each test case
	for _, testcase := range newDataProvider {
		t.Log(testcase.name)

		got := middleware.New(testcase.options)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("New() = %v, want %v", got, testcase.want)
		}
	}
}
