package repositories

import (
	"context"
	"database/sql"

	"auth-microservice-go.v2/pkg/domain/entities"
	"auth-microservice-go.v2/pkg/infrastructure/persistence/postgres"

	"github.com/google/uuid"
)

type UserRepository interface {

	//! Operaciones CRUD basicas para el usuario
	Create(ctx context.Context, user *entities.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	// Delete(ctx context.Context, id uuid.UUID, tx *sql.Tx) error

	//! Operaciones especificas del dominio de autenticacion
	FindByDNI(ctx context.Context, dni string) (*entities.User, error)
	FindByEmail(ctx context.Context, email string) (*entities.User, error)
	FindByTelefono(ctx context.Context, telefono string) (*entities.User, error)
	FindByIdentifier(ctx context.Context, identifier string) (*entities.User, error)

	//! Operaciones especificas de usuario
	// UpdatePassword(ctx context.Context, id uuid.UUID, password string) error
	UpdatePassword(ctx context.Context, id uuid.UUID, password string, tx *sql.Tx) error
	VerifyEmail(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error

	//! listados y paginacion
	List(ctx context.Context, page, limit int) ([]*entities.User, int, error)
	FindByIDs(ctx context.Context, ids []uuid.UUID, page, limit int) ([]*entities.User, int, error)
	ListWithFilters(ctx context.Context, page, limit int, filters map[string]string) ([]*entities.User, int, error)
	// ListWithAdvancedFilters(ctx context.Context, page, limit int, filters map[string]interface{}) ([]*entities.User, int, error)
	ListWithAdvancedFilters(ctx context.Context, params postgres.ListUsersParams) (postgres.ListUsersResult, error)
	ListWithTotalCount(ctx context.Context, params postgres.ListUsersParams) (postgres.ListUsersResult, error)

	// AGREGAR ESTOS MÉTODOS DE TRANSACCIONES:
    BeginTx(ctx context.Context) (*sql.Tx, error)
    CommitTx(tx *sql.Tx) error
    RollbackTx(tx *sql.Tx) error
	

}