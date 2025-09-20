package repositories

import (
	"context"

	"auth-microservice-go.v2/pkg/domain/entities"
	"github.com/google/uuid"
)

type UserEmpresaRoleRepository interface {
	// Operaciones CRUD básicas
	Create(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.UserEmpresaRole, error)
	Update(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Búsquedas por relaciones
	FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	FindByEmpresa(ctx context.Context, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.UserEmpresaRole, error)

	// Operaciones de negocio específicas
	AssignRoleToUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error

	// Consultas agregadas para casos de uso complejos
	FindEmpresasByUserID(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error)
	GetAllUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error)

	FindPermissionsByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]string, error)
	// HasRoleInEmpresa verifica si un usuario tiene un rol específico en una empresa
	// HasRoleInEmpresa(ctx context.Context, userID, empresaID, roleID uuid.UUID) (bool, error)
	
	// GetActiveRolesInEmpresa obtiene roles activos de un usuario en una empresa
	// GetActiveRolesInEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]uuid.UUID, error)

	FindEmpresasWithRolesByUserIDOptimized(ctx context.Context, userID uuid.UUID) ([]*entities.EmpresaConRol, error)
}
