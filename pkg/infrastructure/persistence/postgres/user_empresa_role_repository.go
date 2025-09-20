// pkg/infrastructure/persistence/postgres/user_empresa_role_repository.go
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"auth-microservice-go.v2/pkg/domain/entities"
)

type userEmpresaRoleRepository struct {
	db *sqlx.DB
	findEmpresasStmt     *sql.Stmt  // Prepared statement
}

func (r *userEmpresaRoleRepository) initPreparedStatements() error {
    // Prepared statement para la consulta optimizada
    stmt, err := r.db.Prepare(`
        SELECT 
            uer.empresa_id, 
            ARRAY_AGG(DISTINCT r.name ORDER BY r.name) as roles,
            COALESCE(
                ARRAY_AGG(DISTINCT p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), 
                ARRAY[]::text[]
            ) as permissions
        FROM user_empresa_roles uer
        INNER JOIN roles r ON uer.role_id = r.id
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id
        WHERE uer.user_id = $1 AND uer.active = true
        GROUP BY uer.empresa_id
        ORDER BY MAX(uer.created_at) DESC
    `)
    if err != nil {
        return fmt.Errorf("error preparando statement FindEmpresasWithRoles: %v", err)
    }
    
    r.findEmpresasStmt = stmt
    log.Printf("Prepared statement inicializado correctamente")
    return nil
}


// NewUserEmpresaRoleRepository crea una nueva instancia del repositorio
// func NewUserEmpresaRoleRepository(db *sqlx.DB) *userEmpresaRoleRepository {
// 	return &userEmpresaRoleRepository{
// 		db: db,
// 	}
	
// }
func NewUserEmpresaRoleRepository(db *sqlx.DB) (*userEmpresaRoleRepository, error) {
    repo := &userEmpresaRoleRepository{
        db: db,
    }
    
    // Inicializar prepared statements
    if err := repo.initPreparedStatements(); err != nil {
        return nil, fmt.Errorf("error inicializando prepared statements: %v", err)
    }
    
    return repo, nil
}

// Close cierra los prepared statements
func (r *userEmpresaRoleRepository) Close() error {
    if r.findEmpresasStmt != nil {
        return r.findEmpresasStmt.Close()
    }
    return nil
}

func (r *userEmpresaRoleRepository) Create(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error {
	query := `
		INSERT INTO user_empresa_roles (id, user_id, empresa_id, role_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userEmpresaRole.ID,
		userEmpresaRole.UserID,
		userEmpresaRole.EmpresaID,
		userEmpresaRole.RoleID,
		userEmpresaRole.Active,
		userEmpresaRole.CreatedAt,
		userEmpresaRole.UpdatedAt,
	)

	return err
}

func (r *userEmpresaRoleRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE id = $1
	`

	var userEmpresaRole entities.UserEmpresaRole
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&userEmpresaRole.ID,
		&userEmpresaRole.UserID,
		&userEmpresaRole.EmpresaID,
		&userEmpresaRole.RoleID,
		&userEmpresaRole.Active,
		&userEmpresaRole.CreatedAt,
		&userEmpresaRole.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("relación usuario-empresa-rol no encontrada")
		}
		return nil, err
	}

	return &userEmpresaRole, nil
}

//!roles de usuario en empresa específica
func (r *userEmpresaRoleRepository) FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE user_id = $1 AND empresa_id = $2
	`

	rows, err := r.db.QueryContext(ctx, query, userID, empresaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) FindByEmpresa(ctx context.Context, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE empresa_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, empresaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE role_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) Update(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error {
	query := `
		UPDATE user_empresa_roles
		SET user_id = $1, empresa_id = $2, role_id = $3, active = $4, updated_at = $5
		WHERE id = $6
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userEmpresaRole.UserID,
		userEmpresaRole.EmpresaID,
		userEmpresaRole.RoleID,
		userEmpresaRole.Active,
		time.Now(),
		userEmpresaRole.ID,
	)

	return err
}

func (r *userEmpresaRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_empresa_roles WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *userEmpresaRoleRepository) AssignRoleToUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	// Verificar si ya existe la relación
	existingRoles, err := r.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err == nil && len(existingRoles) > 0 {
		for _, existing := range existingRoles {
			if existing.RoleID == roleID {
				if !existing.Active {
					// Si existe pero está inactivo, lo activamos
					existing.Active = true
					existing.UpdatedAt = time.Now()
					return r.Update(ctx, existing)
				}
				return errors.New("el usuario ya tiene este rol en la empresa")
			}
		}
	}

	// Crear nueva relación
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    userID,
		EmpresaID: empresaID,
		RoleID:    roleID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return r.Create(ctx, userEmpresaRole)
}


//!remover rol específico
func (r *userEmpresaRoleRepository) RemoveRoleFromUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	query := `
		DELETE FROM user_empresa_roles 
		WHERE user_id = $1 AND empresa_id = $2 AND role_id = $3
	`

	_, err := r.db.ExecContext(ctx, query, userID, empresaID, roleID)
	return err
}


//! empresas donde usuario tiene acceso
func (r *userEmpresaRoleRepository) FindEmpresasByUserID(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	var empresaIDs []uuid.UUID
	query := `
		SELECT DISTINCT empresa_id
		FROM user_empresa_roles
		WHERE user_id = $1 AND active = true
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var empresaID uuid.UUID
		if err := rows.Scan(&empresaID); err != nil {
			return nil, err
		}
		empresaIDs = append(empresaIDs, empresaID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return empresaIDs, nil

}


//!usuarios de empresa con filtro de rol
func (r *userEmpresaRoleRepository) GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error) {
    var query string
    var args []interface{}
    
    if roleFilter != "" {
        query = `
            SELECT uer.user_id, MIN(uer.created_at) as min_created_at
            FROM user_empresa_roles uer
            JOIN roles r ON uer.role_id = r.id
            WHERE uer.empresa_id = $1 AND uer.active = true AND r.name = $2
            GROUP BY uer.user_id
            ORDER BY min_created_at
        `
        args = []interface{}{empresaID, roleFilter}
    } else {
        query = `
            SELECT user_id, MIN(created_at) as min_created_at
            FROM user_empresa_roles 
            WHERE empresa_id = $1 AND active = true
            GROUP BY user_id
            ORDER BY min_created_at
        `
        args = []interface{}{empresaID}
    }
    
    rows, err := r.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var userIDs []uuid.UUID
    for rows.Next() {
        var userID uuid.UUID
        var createdAt time.Time
        if err := rows.Scan(&userID, &createdAt); err != nil {
            return nil, err
        }
        userIDs = append(userIDs, userID)
    }
    
    return userIDs, nil
}

//!Esta función se usa para obtener todos los roles que un usuario tiene en diferentes empresas, por ejemplo, para determinar los permisos o accesos del usuario en un sistema multiempresa.
func (r *userEmpresaRoleRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
    query := `
        SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
        FROM user_empresa_roles
        WHERE user_id = $1 AND active = true
    `
    
    rows, err := r.db.QueryContext(ctx, query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    userEmpresaRoles := []*entities.UserEmpresaRole{}
    for rows.Next() {
        var uer entities.UserEmpresaRole
        err := rows.Scan(
            &uer.ID,
            &uer.UserID,
            &uer.EmpresaID,
            &uer.RoleID,
            &uer.Active,
            &uer.CreatedAt,
            &uer.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        userEmpresaRoles = append(userEmpresaRoles, &uer)
    }
    
    if err = rows.Err(); err != nil {
        return nil, err
    }
    
    return userEmpresaRoles, nil
}

//!Esta función se usa para obtener una lista de usuarios que pertenecen a una empresa específica, opcionalmente filtrados por un rol (por ejemplo, "admin", "user", etc.). Es útil para casos como listar todos los administradores de una empresa o verificar qué usuarios están asociados a ella
func (r *userEmpresaRoleRepository) GetAllUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error) {
    var query string
    var args []interface{}
    
    if roleFilter != "" {
        query = `
            SELECT DISTINCT uer.user_id
            FROM user_empresa_roles uer
            JOIN roles r ON uer.role_id = r.id
            WHERE uer.empresa_id = $1 AND uer.active = true AND r.name = $2
        `
        args = []interface{}{empresaID, roleFilter}
    } else {
        query = `
            SELECT DISTINCT user_id
            FROM user_empresa_roles 
            WHERE empresa_id = $1 AND active = true
        `
        args = []interface{}{empresaID}
    }
    
    rows, err := r.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var userIDs []uuid.UUID
    for rows.Next() {
        var userID uuid.UUID
        if err := rows.Scan(&userID); err != nil {
            return nil, err
        }
        userIDs = append(userIDs, userID)
    }
    
    return userIDs, nil
}


func (r *userEmpresaRoleRepository) FindPermissionsByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]string, error) {
    query := `
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        JOIN user_empresa_roles uer ON r.id = uer.role_id
        WHERE uer.user_id = $1 AND uer.empresa_id = $2 AND uer.active = true
    `

    rows, err := r.db.QueryContext(ctx, query, userID, empresaID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var permissions []string
    for rows.Next() {
        var permName string
        if err := rows.Scan(&permName); err != nil {
            return nil, err
        }
        permissions = append(permissions, permName)
    }

    return permissions, nil
}



// Usar el prepared statement en la consulta optimizada
func (r *userEmpresaRoleRepository) FindEmpresasWithRolesByUserIDOptimized(ctx context.Context, userID uuid.UUID) ([]*entities.EmpresaConRol, error) {
    log.Printf("Ejecutando consulta optimizada con prepared statement para usuario: %s", userID)

    // Usar el prepared statement en lugar de QueryContext
    rows, err := r.findEmpresasStmt.QueryContext(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("error ejecutando prepared statement: %v", err)
    }
    defer rows.Close()

    var empresas []*entities.EmpresaConRol
    for rows.Next() {
        var empresaID uuid.UUID
        var roles, permissions pq.StringArray

        if err := rows.Scan(&empresaID, &roles, &permissions); err != nil {
            log.Printf("Error scanning row: %v", err)
            continue
        }

        empresas = append(empresas, &entities.EmpresaConRol{
            EmpresaID:   empresaID,
            Roles:       []string(roles),
            Permissions: []string(permissions),
        })
    }

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterando rows: %v", err)
    }

    log.Printf("Consulta optimizada con prepared statement completada: %d empresas", len(empresas))
    return empresas, nil
}