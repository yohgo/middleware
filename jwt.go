package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// Condition is a callback that allows you to add further checks.
type Condition func(claims *Claims, r *http.Request) bool

// JWTAuthenticate is a JWT Authentication middleware operation.
func (m *Middleware) JWTAuthenticate(w http.ResponseWriter, r *http.Request) bool {
	// Attempt to get token string from the Authorization header
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	// Attempt to parse the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return m.Options.JWTKey, nil
	})

	if err != nil || !parsedToken.Valid {
		m.ResolveJSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "Access to the requested resource is denied")
		return false
	}

	// Setting the access token in the request context.
	*r = *r.WithContext(context.WithValue(r.Context(), m.Options.JWTContextKey, parsedToken))

	return true
}

// JWTAuthorize is an authorization middleware operation.
func (m *Middleware) JWTAuthorize(permissions []string, conditions ...Condition) Operation {
	return func(w http.ResponseWriter, r *http.Request) bool {
		// Attempting to get access token claims from the request context
		claims := NewClaims(r.Context().Value(m.Options.JWTContextKey))
		if claims == nil {
			m.ResolveJSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "Access to the requested resource is denied")
			return false
		}

		// Checking if the access token claims contains at least one of the required permission
		if !claims.HasPermissions(permissions, false) {
			m.ResolveJSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "Access to the requested resource is denied")
			return false
		}

		// Check if all conditions are satisfied
		for _, condition := range conditions {
			if !condition(claims, r) {
				m.ResolveJSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "Access to the requested resource is denied")
				return false
			}
		}

		return true
	}
}
