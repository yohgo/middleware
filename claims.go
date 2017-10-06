package middleware

import (
	jwt "github.com/dgrijalva/jwt-go"
)

// Claims is a JWT token claims.
type Claims struct {
	UserID      uint64
	Role        string
	Permissions []string
}

// NewClaims creates a new Claims based on the provided access token.
func NewClaims(accessToken interface{}) *Claims {
	token, ok := accessToken.(*jwt.Token)
	if !ok {
		return nil
	}

	claim, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	userID, ok := claim["uid"].(float64)
	if !ok {
		return nil
	}

	role, ok := claim["iur"].(string)
	if !ok {
		return nil
	}

	permissions, ok := claim["iup"].([]interface{})
	if !ok {
		return nil
	}

	var permissionSlice []string
	for _, permission := range permissions {
		if aPermission, ok := permission.(string); ok {
			permissionSlice = append(permissionSlice, aPermission)
		}
	}

	return &Claims{
		UserID:      uint64(userID),
		Role:        role,
		Permissions: permissionSlice,
	}
}

// HasPermission checks if the token claims contains a particular permission.
func (claims *Claims) HasPermission(permission string) bool {
	for _, aPermission := range claims.Permissions {
		if permission == aPermission {
			return true
		}
	}

	return false
}

// HasPermissions checks if the token claims contains the specified permissions.
// The all parameter will check if the token claims contains all the specified permissions.
func (claims *Claims) HasPermissions(permissions []string, all bool) bool {
	for _, permission := range permissions {
		pExists := claims.HasPermission(permission)
		// Checks if the token has all the permissions
		// Checks the token has at least one of the permissions
		if (all && !pExists) || (!all && pExists) {
			return !all
		}
	}

	return all
}

// IsOwner checks if the token claims belongs to the resource owner.
func (claims *Claims) IsOwner(userID uint64) bool {
	return (claims.UserID == userID)
}
