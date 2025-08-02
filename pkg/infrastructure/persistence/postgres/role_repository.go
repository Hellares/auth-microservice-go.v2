package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"auth-microservice-go.v2/pkg/domain/entities"
)

type roleRepository struct {
	db *sqlx.DB
}

func NewRoleRepository(db *sqlx.DB) *roleRepository {
	return &roleRepository{
		db: db,
	}
}

func (r *roleRepository) Create(ctx context.Context, role *entities.Role) error {
    query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(
		ctx, 
		query, 
		role.ID, 
		role.Name, 
		role.Description, 
		role.CreatedAt, 
		role.UpdatedAt,
	)
	return err
}

func (r *roleRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	var role entities.Role
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("rol no encontrado")
		}
		return nil, err
	}

	return &role, nil
}

func (r *roleRepository) FindByName(ctx context.Context, name string) (*entities.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1
	`

	var role entities.Role
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("rol no encontrado")
		}
		return nil, err
	}

	return &role, nil
}

func (r *roleRepository) Update(ctx context.Context, role *entities.Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		role.Name,
		role.Description,
		time.Now(),
		role.ID,
	)

	return err
}

func (r *roleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM roles WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *roleRepository) List(ctx context.Context) ([]*entities.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []*entities.Role{}
	for rows.Next() {
		var role entities.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *roleRepository) FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_empresa_roles uer ON r.id = uer.role_id
		WHERE uer.user_id = $1 AND uer.empresa_id = $2 AND uer.active = true
	`

	rows, err := r.db.QueryContext(ctx, query, userID, empresaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []*entities.Role{}
	for rows.Next() {
		var role entities.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *roleRepository) FindAllByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.Role, error) {
    query := `
        SELECT DISTINCT r.id, r.name, r.description, r.created_at, r.updated_at
        FROM roles r
        JOIN user_empresa_roles uer ON r.id = uer.role_id
        WHERE uer.user_id = $1 AND uer.active = true
        ORDER BY r.name
    `
    
    rows, err := r.db.QueryContext(ctx, query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var roles []*entities.Role
    for rows.Next() {
        var role entities.Role
        err := rows.Scan(
            &role.ID,
            &role.Name,
            &role.Description,
            &role.CreatedAt,
            &role.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        roles = append(roles, &role)
    }
    
    if err = rows.Err(); err != nil {
        return nil, err
    }
    
    return roles, nil
}