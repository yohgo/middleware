package middleware_test

import (
	"reflect"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/yohgo/middleware"
)

// newClaimsDataProvider provides data for the TestNewClaims function.
var newClaimsDataProvider = []struct {
	name string
	data interface{}
	want *middleware.Claims
}{
	{
		name: "A successful claims creation of claims for user ID 1",
		data: &jwt.Token{
			Valid: true,
			Claims: jwt.MapClaims{
				"uid": float64(1),
				"iur": "User",
				"iup": []interface{}{"user.add", "user.update", "user.delete"},
			},
		},
		want: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
	},
	{
		name: "A successful claims creation of claims user ID 2",
		data: &jwt.Token{
			Valid: true,
			Claims: jwt.MapClaims{
				"uid": float64(2),
				"iur": "User",
				"iup": []interface{}{"event.add", "event.update", "event.delete"},
			},
		},
		want: &middleware.Claims{
			UserID:      2,
			Role:        "User",
			Permissions: []string{"event.add", "event.update", "event.delete"},
		},
	},
	{
		name: "A failed claims creation due to a invalid token data",
		data: "invalid token data",
		want: nil,
	},
	{
		name: "A failed claims creation due to missing claims",
		data: &jwt.Token{Valid: true},
		want: nil,
	},
	{
		name: "A failed claims creation due to an invalid user ID",
		data: &jwt.Token{
			Valid: true,
			Claims: jwt.MapClaims{
				"uid": "invalid_user_id",
				"iur": "User",
				"iup": []interface{}{"event.add", "event.update", "event.delete"},
			},
		},
		want: nil,
	},
	{
		name: "A failed claims creation due to an invalid user role",
		data: &jwt.Token{
			Valid: true,
			Claims: jwt.MapClaims{
				"uid": float64(1),
				"iur": 1,
				"iup": []interface{}{"event.add", "event.update", "event.delete"},
			},
		},
		want: nil,
	},
	{
		name: "A failed claims creation due to invalid user permissions",
		data: &jwt.Token{
			Valid: true,
			Claims: jwt.MapClaims{
				"uid": float64(1),
				"iur": "Admin",
				"iup": 2,
			},
		},
		want: nil,
	},
}

// TestNewClaims tests the NewClaims method.
func TestNewClaims(t *testing.T) {
	t.Log("NewClaims")
	// Check each test case
	for _, testcase := range newClaimsDataProvider {
		t.Log(testcase.name)

		got := middleware.NewClaims(testcase.data)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("NewClaims(%v) = %v, want %v", testcase.data, got, testcase.want)
		}
	}
}

// hasPermissionDataProvider provides data for the TestHasPermission function.
var hasPermissionDataProvider = []struct {
	name       string
	permission string
	claims     *middleware.Claims
	want       bool
}{
	{
		name:       "A successful user permission check for 'user.add'",
		permission: "user.add",
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: true,
	},
	{
		name:       "A successful user permission check for 'user.delete'",
		permission: "user.delete",
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: true,
	},
	{
		name:       "A failed user permission check for 'event.delete'",
		permission: "event.delete",
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: false,
	},
}

// TestHasPermission tests the HasPermission method.
func TestHasPermission(t *testing.T) {
	t.Log("HasPermission")
	// Check each test case
	for _, testcase := range hasPermissionDataProvider {
		t.Log(testcase.name)

		got := testcase.claims.HasPermission(testcase.permission)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("HasPermission(%v) = %v, want %v", testcase.permission, got, testcase.want)
		}
	}
}

// hasPermissionsDataProvider provides data for the TestHasPermissions function.
var hasPermissionsDataProvider = []struct {
	name        string
	permissions []string
	all         bool
	claims      *middleware.Claims
	want        bool
}{
	{
		name:        "A successful all user permissions check for 'user.add', 'user.update'",
		permissions: []string{"user.add", "user.update"},
		all:         true,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: true,
	},
	{
		name:        "A successful not all user permissions check for 'user.view', 'user.add'",
		permissions: []string{"user.view", "user.add"},
		all:         false,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: true,
	},
	{
		name:        "A failed all user permissions check for 'user.add', 'user.view'",
		permissions: []string{"user.add", "user.view"},
		all:         true,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: false,
	},
	{
		name:        "A failed not all user permissions check for 'user.view', 'user.edit'",
		permissions: []string{"user.view", "user.edit"},
		all:         false,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: false,
	},
}

// TestHasPermissions tests the HasPermissions method.
func TestHasPermissions(t *testing.T) {
	t.Log("HasPermissions")
	// Check each test case
	for _, testcase := range hasPermissionsDataProvider {
		t.Log(testcase.name)

		got := testcase.claims.HasPermissions(testcase.permissions, testcase.all)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("HasPermissions(%v, %v) = %v, want %v", testcase.permissions, testcase.all, got, testcase.want)
		}
	}
}

// isOwnerDataProvider provides data for the TestIsOwner function.
var isOwnerDataProvider = []struct {
	name   string
	userID uint64
	claims *middleware.Claims
	want   bool
}{
	{
		name:   "A successful user owner check for claims with user ID 1",
		userID: 1,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: true,
	},
	{
		name:   "A failed user owner check for claims with mismatch user ID",
		userID: 1,
		claims: &middleware.Claims{
			UserID:      2,
			Role:        "User",
			Permissions: []string{"user.add", "user.update", "user.delete"},
		},
		want: false,
	},
	{
		name:   "A failed user owner check for claims with mismatch user ID and Admin role",
		userID: 3,
		claims: &middleware.Claims{
			UserID:      2,
			Role:        "Admin",
			Permissions: []string{"user.create", "user.add", "user.update", "user.delete"},
		},
		want: false,
	},
	{
		name:   "A failed user owner check for claims with mismatch user ID and Guest role",
		userID: 2,
		claims: &middleware.Claims{
			UserID:      1,
			Role:        "Guest",
			Permissions: []string{"user.create"},
		},
		want: false,
	},
}

// TestIsOwner tests the IsOwner method.
func TestIsOwner(t *testing.T) {
	t.Log("IsOwner")
	// Check each test case
	for _, testcase := range isOwnerDataProvider {
		t.Log(testcase.name)

		got := testcase.claims.IsOwner(testcase.userID)

		// Check the response
		if !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("IsOwner(%v) = %v, want %v", testcase.userID, got, testcase.want)
		}
	}
}
