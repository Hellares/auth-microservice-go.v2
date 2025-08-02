package repositories

import (
    "context"
    "github.com/google/uuid"
    "auth-microservice-go.v2/pkg/domain/entities"
)

type SystemRoleRepository interface {
    Create(ctx context.Context, systemRole *entities.SystemRole) error
    FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.SystemRole, error)
    HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
    Delete(ctx context.Context, id uuid.UUID) error
}