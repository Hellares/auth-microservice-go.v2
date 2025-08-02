package repositories

import (
	"context"

	"github.com/google/uuid"
	"auth-microservice-go.v2/pkg/domain/entities"
)

type PermissionRepository interface {
	// Operaciones CRUD básicas
	Create(ctx context.Context, permission *entities.Permission) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.Permission, error)
	FindByName(ctx context.Context, name string) (*entities.Permission, error)
	Update(ctx context.Context, permission *entities.Permission) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]*entities.Permission, error)

	// Consultas específicas del dominio
	FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error)
}