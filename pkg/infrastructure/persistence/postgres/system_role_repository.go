package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"auth-microservice-go.v2/pkg/domain/entities"
)

// ErrSystemRoleNotFound se devuelve cuando un rol de sistema no se encuentra en la base de datos.
var ErrSystemRoleNotFound = errors.New("rol de sistema no encontrado")

type systemRoleRepository struct {
	db *sqlx.DB
}

// NewSystemRoleRepository crea una nueva instancia del repositorio de roles de sistema.
func NewSystemRoleRepository(db *sqlx.DB) *systemRoleRepository {
	return &systemRoleRepository{
		db: db,
	}
}

// Create inserta un nuevo rol de sistema en la base de datos, soportando transacciones opcionales.
// Devuelve un error si la operación falla o si los datos del rol son inválidos.
func (r *systemRoleRepository) Create(ctx context.Context, systemRole *entities.SystemRole) error {
	if systemRole == nil || systemRole.ID == uuid.Nil || systemRole.UserID == uuid.Nil || systemRole.RoleName == "" {
		return errors.New("rol de sistema inválido")
	}

	query := `
		INSERT INTO system_roles (id, user_id, role_name, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	db := r.db
	
	_, err := db.ExecContext(
		ctx,
		query,
		systemRole.ID,
		systemRole.UserID,
		systemRole.RoleName,
		systemRole.Active,
		systemRole.CreatedAt,
		systemRole.UpdatedAt,
	)

	return err
}

// Update actualiza un rol de sistema existente en la base de datos, soportando transacciones opcionales.
// Devuelve un error si la operación falla o si los datos del rol son inválidos.
func (r *systemRoleRepository) Update(ctx context.Context, systemRole *entities.SystemRole) error {
	if systemRole == nil || systemRole.ID == uuid.Nil || systemRole.RoleName == "" {
		return errors.New("rol de sistema inválido")
	}

	query := `
		UPDATE system_roles
		SET role_name = $2, active = $3, updated_at = $4
		WHERE id = $1
	`

	db := r.db
	
	_, err := db.ExecContext(
		ctx,
		query,
		systemRole.ID,
		systemRole.RoleName,
		systemRole.Active,
		time.Now(),
	)

	return err
}

// FindByUserID obtiene todos los roles de sistema activos de un usuario por su ID.
// Devuelve una lista de roles o un error si falla la consulta.
func (r *systemRoleRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.SystemRole, error) {
	if userID == uuid.Nil {
		return nil, errors.New("ID de usuario inválido")
	}

	query := `
		SELECT id, user_id, role_name, active, created_at, updated_at
		FROM system_roles
		WHERE user_id = $1 AND active = true
	`

	var systemRoles []*entities.SystemRole
	err := r.db.SelectContext(ctx, &systemRoles, query, userID)
	if err != nil {
		return nil, err
	}

	return systemRoles, nil
}

// HasSystemRole verifica si un usuario tiene un rol específico del sistema que esté activo.
// Devuelve true si el rol existe, false si no, o un error si falla la consulta.
func (r *systemRoleRepository) HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	if userID == uuid.Nil || roleName == "" {
		return false, errors.New("parámetros inválidos")
	}

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM system_roles
			WHERE user_id = $1 AND role_name = $2 AND active = true
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, roleName).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// Delete elimina un rol de sistema por su ID.
// Devuelve un error si la operación falla.
func (r *systemRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("ID de rol inválido")
	}

	query := `DELETE FROM system_roles WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}