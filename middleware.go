package middleware

import (
	"net/http"

	"github.com/yohgo/pastry"
)

// Middleware is a struct that defines middleware.
type Middleware struct {
	Options Options
	pastry.JSONResolver
}

// Operation is a middleware operation.
type Operation func(w http.ResponseWriter, r *http.Request) bool

// New creates a new Middleware.
func New(options Options) *Middleware {
	return &Middleware{
		Options: options,
	}
}

// Add adds middleware operations to a Handler.
func (m *Middleware) Add(next http.HandlerFunc, operations ...Operation) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, operation := range operations {
			if !operation(w, r) {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
