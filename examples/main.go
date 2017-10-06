package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/yohgo/middleware"
	"github.com/yohgo/mux"
)

func main() {
	mid := middleware.New(middleware.Options{
		JWTKey:        []byte("secret"),
		JWTContextKey: "token",
	})

	// Create a router.
	router := mux.NewRouter(mux.Routes{
		{
			Name:        "Public Resource",
			Method:      "GET",
			Path:        "/users",
			HandlerFunc: hello,
		},
		{
			Name:   "Protected Resource",
			Method: "GET",
			Path:   "/users/{userId}",
			HandlerFunc: mid.Add(
				secureHello,
				mid.JWTAuthenticate,
				mid.JWTAuthorize([]string{"user.retrieve"}, isMe),
			),
		},
	})

	// Attempt to start server.
	if err := http.ListenAndServe(":1234", router); err != nil {
		log.Fatal("Failed to start server")
	}
}

// hello is a simple unprotected resource.
func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello World"))
}

// secureHello is a simple protected resource.
func secureHello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello Secure World"))
}

// isMe is a condition we want to check along with authorization.
func isMe(claims *middleware.Claims, r *http.Request) bool {
	userID, err := strconv.ParseUint(strings.Split(r.URL.Path, "/")[2], 10, 64)
	if err != nil {
		return false
	}

	return claims.IsOwner(userID)
}
