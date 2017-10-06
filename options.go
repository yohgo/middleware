package middleware

// Options is a struct for specifying middleware configuration options.
type Options struct {
	JWTKey        []byte
	JWTContextKey string
}
