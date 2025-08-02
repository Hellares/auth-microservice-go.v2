package repositories

import (
	"context"

	"github.com/google/uuid"
	"auth-microservice-go.v2/pkg/domain/entities"
)


type RoleRepository interface {
	// Operaciones CRUD básicas
	Create(ctx context.Context, role *entities.Role) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.Role, error)
	FindByName(ctx context.Context, name string) (*entities.Role, error)
	Update(ctx context.Context, role *entities.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]*entities.Role, error)

	// Consultas específicas del dominio
	FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error)
	FindAllByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.Role, error)
}