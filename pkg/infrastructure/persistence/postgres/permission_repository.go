package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"auth-microservice-go.v2/pkg/domain/entities"
)

type permissionRepository struct {
	db *sqlx.DB
}

// NewPermissionRepository crea una nueva instancia del repositorio de permisos
func NewPermissionRepository(db *sqlx.DB) *permissionRepository {
	return &permissionRepository{
		db: db,
	}
}

func (r *permissionRepository) Create(ctx context.Context, permission *entities.Permission) error {
	query := `
		INSERT INTO permissions (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		permission.ID,
		permission.Name,
		permission.Description,
		permission.CreatedAt,
		permission.UpdatedAt,
	)

	return err
}

func (r *permissionRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.Permission, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM permissions
		WHERE id = $1
	`

	var permission entities.Permission
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("permiso no encontrado")
		}
		return nil, err
	}

	return &permission, nil
}

func (r *permissionRepository) FindByName(ctx context.Context, name string) (*entities.Permission, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM permissions
		WHERE name = $1
	`

	var permission entities.Permission
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("permiso no encontrado")
		}
		return nil, err
	}

	return &permission, nil
}

func (r *permissionRepository) Update(ctx context.Context, permission *entities.Permission) error {
	query := `
		UPDATE permissions
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		permission.Name,
		permission.Description,
		permission.UpdatedAt,
		permission.ID,
	)

	return err
}

func (r *permissionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM permissions WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *permissionRepository) List(ctx context.Context) ([]*entities.Permission, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM permissions
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []*entities.Permission{}
	for rows.Next() {
		var permission entities.Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return permissions, nil
}

func (r *permissionRepository) FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []*entities.Permission{}
	for rows.Next() {
		var permission entities.Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return permissions, nil
}