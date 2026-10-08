package access

import (
	"context"
	"errors"
)

// Assignment is one Identity Center role assignment on an account.
type Assignment struct {
	RoleConfiguration string `json:"role_configuration"`
	RoleName          string `json:"role_name"`
	PrincipalID       string `json:"principal_id"`
	PrincipalName     string `json:"principal_name"`
	PrincipalType     string `json:"principal_type"` // User | Group
}

// Directory is Cloud Identity Center.
type Directory interface {
	EnsureRoleConfiguration(ctx context.Context, name, description, policy string, hours int) (string, error)
	UserID(ctx context.Context, email string) (string, bool, error)
	Assign(ctx context.Context, roleConfiguration string, account int64, userID string) error
	Unassign(ctx context.Context, roleConfiguration string, account int64, userID string) error
	Assignments(ctx context.Context, account int64) ([]Assignment, error)
}

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
	ErrState    = errors.New("not in a state that allows this")
)
