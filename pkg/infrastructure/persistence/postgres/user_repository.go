// pkg/infrastructure/persistence/postgres/user_repository.go
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"auth-microservice-go.v2/pkg/domain/entities"
)

// ================================================================
// TIPOS OPTIMIZADOS PARA FILTROS Y PAGINACIÓN
// ================================================================

// ListUsersParams - Parámetros para búsqueda avanzada de usuarios
type ListUsersParams struct {
	// Filtros básicos
	Status   *entities.UserStatus `json:"status,omitempty"`
	Verified *bool                `json:"verified,omitempty"`
	
	// Búsqueda de texto (usa full-text search)
	Search *string `json:"search,omitempty"`
	
	// Filtros específicos
	IDs         []uuid.UUID `json:"ids,omitempty"`
	Departamento *string     `json:"departamento,omitempty"`
	Provincia   *string     `json:"provincia,omitempty"`
	Distrito    *string     `json:"distrito,omitempty"`
	
	// Filtros de fecha
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	LastLoginAfter *time.Time `json:"last_login_after,omitempty"`
	
	// Paginación
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	
	// Ordenamiento
	SortBy    *string `json:"sort_by,omitempty"`    // "created_at", "last_login", "relevance"
	SortOrder *string `json:"sort_order,omitempty"` // "asc", "desc"
}

// ListUsersResult - Resultado optimizado con metadata de paginación
type ListUsersResult struct {
	Users       []*entities.User `json:"users"`
	HasNextPage bool             `json:"has_next_page"`
	TotalCount  *int             `json:"total_count,omitempty"` // Solo cuando se requiera
	Metadata    *QueryMetadata   `json:"metadata,omitempty"`
}

// QueryMetadata - Metadata adicional para debugging y optimización
type QueryMetadata struct {
	ExecutionTime time.Duration `json:"execution_time"`
	QueryUsedFTS  bool          `json:"query_used_fts"` // Si usó full-text search
	IndexesUsed   []string      `json:"indexes_used,omitempty"`
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *userRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Create(ctx context.Context, user *entities.User) error {
	query := `
		INSERT INTO users (
			id, dni, email, password, nombres, apellido_paterno, apellido_materno, 
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia, 
			distrito, direccion_completa, avatar_url, status, verified, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.ID,
		user.DNI,
		user.Email,
		user.Password,
		user.Nombres,
		user.ApellidoPaterno,
		user.ApellidoMaterno,
		user.NombresCompletos,
		user.FechaNacimiento,
		user.Telefono,
		user.Departamento,
		user.Provincia,
		user.Distrito,
		user.DireccionCompleta,
		user.AvatarURL,
		user.Status,
		user.Verified,
		user.CreatedAt,
		user.UpdatedAt,
	)

	return err
}

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuario no encontrado")
		}
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *userRepository) FindByDNI(ctx context.Context, dni string) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE dni = $1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, dni).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuario no encontrado")
		}
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuario no encontrado")
		}
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *userRepository) FindByPhone(ctx context.Context, phone string) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE telefono = $1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, phone).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuario no encontrado")
		}
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *entities.User) error {
	query := `
		UPDATE users
		SET 
			email = $1,
			nombres = $2,
			apellido_paterno = $3,
			apellido_materno = $4,
			nombres_completos = $5,
			fecha_nacimiento = $6,
			telefono = $7,
			departamento = $8,
			provincia = $9,
			distrito = $10,
			direccion_completa = $11,
			avatar_url = $12,
			status = $13,
			verified = $14,
			updated_at = $15
		WHERE id = $16
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.Email,
		user.Nombres,
		user.ApellidoPaterno,
		user.ApellidoMaterno,
		user.NombresCompletos,
		user.FechaNacimiento,
		user.Telefono,
		user.Departamento,
		user.Provincia,
		user.Distrito,
		user.DireccionCompleta,
		user.AvatarURL,
		user.Status,
		user.Verified,
		time.Now(),
		user.ID,
	)

	return err
}

func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *userRepository) List(ctx context.Context, page, limit int) ([]*entities.User, int, error) {
	// Consulta para obtener la cantidad total de usuarios
	countQuery := `SELECT COUNT(*) FROM users`
	var total int
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Calcular offset
	offset := (page - 1) * limit

	// Consulta para obtener los usuarios paginados
	query := `
		SELECT 
			id, dni, email, nombres, apellido_paterno, apellido_materno,
			nombres_completos, telefono, avatar_url, status, verified, 
			last_login, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := []*entities.User{}
	for rows.Next() {
		var user entities.User
		var lastLogin sql.NullTime

		err := rows.Scan(
			&user.ID,
			&user.DNI,
			&user.Email,
			&user.Nombres,
			&user.ApellidoPaterno,
			&user.ApellidoMaterno,
			&user.NombresCompletos,
			&user.Telefono,
			&user.AvatarURL,
			&user.Status,
			&user.Verified,
			&lastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, id uuid.UUID, password string, tx *sql.Tx) error {
	query := `
        UPDATE users
        SET 
            password = $1,
            updated_at = $2
        WHERE id = $3
    `

	// Si hay transacción, usarla; si no, usar conexión normal
	if tx != nil {
		_, err := tx.ExecContext(ctx, query, password, time.Now(), id)
		return err
	} else {
		_, err := r.db.ExecContext(ctx, query, password, time.Now(), id)
		return err
	}
}

func (r *userRepository) VerifyEmail(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET 
			verified = true,
			updated_at = $1
		WHERE id = $2
	`

	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	return err
}

func (r *userRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error {
	query := `
		UPDATE users
		SET 
			status = $1,
			updated_at = $2
		WHERE id = $3
	`

	_, err := r.db.ExecContext(ctx, query, status, time.Now(), id)
	return err
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET 
			last_login = $1,
			updated_at = $2
		WHERE id = $3
	`

	_, err := r.db.ExecContext(ctx, query, time.Now(), time.Now(), id)
	return err
}

func (r *userRepository) FindByIdentifier(ctx context.Context, identifier string) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE dni = $1 OR email = $1 OR telefono = $1
		LIMIT 1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, identifier).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuario no encontrado")
		}
		return nil, err
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (r *userRepository) FindByIDs(ctx context.Context, ids []uuid.UUID, page, limit int) ([]*entities.User, int, error) {
	if len(ids) == 0 {
		return []*entities.User{}, 0, nil
	}

	// Contar total
	countQuery := `
		SELECT COUNT(*) 
		FROM users 
		WHERE id = ANY($1)
	`
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, pq.Array(ids)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Obtener usuarios paginados
	offset := (page - 1) * limit
	query := `
		SELECT 
			id, dni, email, nombres, apellido_paterno, apellido_materno,
			nombres_completos, telefono, avatar_url, status, verified, 
			last_login, created_at, updated_at
		FROM users
		WHERE id = ANY($1)
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(ids), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*entities.User
	for rows.Next() {
		var user entities.User
		var lastLogin sql.NullTime

		err := rows.Scan(
			&user.ID,
			&user.DNI,
			&user.Email,
			&user.Nombres,
			&user.ApellidoPaterno,
			&user.ApellidoMaterno,
			&user.NombresCompletos,
			&user.Telefono,
			&user.AvatarURL,
			&user.Status,
			&user.Verified,
			&lastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	return users, total, nil
}

// func (r *userRepository) ListWithFilters(ctx context.Context, page, limit int, filters map[string]string) ([]*entities.User, int, error) {
// 	// Base de la consulta
// 	baseQuery := `FROM users WHERE 1=1`
// 	countQuery := `SELECT COUNT(*) ` + baseQuery
// 	listQuery := `
// SELECT
// 	id, dni, email, password, nombres, apellido_paterno, apellido_materno,
// 	nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
// 	distrito, direccion_completa, avatar_url, status, verified, last_login,
// 	created_at, updated_at
// ` + baseQuery

// 	// Variables para los argumentos
// 	args := []interface{}{}
// 	argIndex := 1

// 	// Aplicar filtros
// 	if status, ok := filters["status"]; ok {
// 		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
// 		args = append(args, status)
// 		argIndex++
// 	}

// 	if search, ok := filters["search"]; ok {
// 		// Búsqueda por nombre, apellido, email o DNI
// baseQuery += fmt.Sprintf(` AND (
// 	dni ILIKE $%d OR
// 	email ILIKE $%d OR
// 	nombres ILIKE $%d OR
// 	apellido_paterno ILIKE $%d OR
// 	apellido_materno ILIKE $%d OR
// 	telefono ILIKE $%d
// )`, argIndex, argIndex, argIndex, argIndex, argIndex, argIndex)
// args = append(args, "%"+search+"%")
// argIndex++
// 	}

// 	// Actualizar queries con los filtros
// 	countQuery = `SELECT COUNT(*) ` + baseQuery
// 	listQuery = `
// SELECT
// 	id, dni, email, password, nombres, apellido_paterno, apellido_materno,
// 	nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
// 	distrito, direccion_completa, avatar_url, status, verified, last_login,
// 	created_at, updated_at
// ` + baseQuery + ` ORDER BY created_at DESC LIMIT $` + fmt.Sprintf("%d", argIndex) + ` OFFSET $` + fmt.Sprintf("%d", argIndex+1)

// 	// Añadir limit y offset a los argumentos
// 	args = append(args, limit, (page-1)*limit)

// 	// Obtener total
// 	var total int
// 	err := r.db.QueryRowContext(ctx, countQuery, args[:argIndex-1]...).Scan(&total)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	// Ejecutar consulta con paginación
// 	rows, err := r.db.QueryContext(ctx, listQuery, args...)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	defer rows.Close()

// 	// Procesar resultados
// 	var users []*entities.User
// 	for rows.Next() {
// 		var user entities.User
// 		var lastLogin sql.NullTime

// 		err := rows.Scan(
// &user.ID,
// &user.DNI,
// &user.Email,
// &user.Password,
// &user.Nombres,
// &user.ApellidoPaterno,
// &user.ApellidoMaterno,
// &user.NombresCompletos,
// &user.FechaNacimiento,
// &user.Telefono,
// &user.Departamento,
// &user.Provincia,
// &user.Distrito,
// &user.DireccionCompleta,
// &user.AvatarURL,
// &user.Status,
// &user.Verified,
// &lastLogin,
// &user.CreatedAt,
// &user.UpdatedAt,
// 		)
// 		if err != nil {
// 			return nil, 0, err
// 		}

// 		if lastLogin.Valid {
// 			user.LastLogin = &lastLogin.Time
// 		}

// 		users = append(users, &user)
// 	}

// 	if err = rows.Err(); err != nil {
// 		return nil, 0, err
// 	}

// 	return users, total, nil
// }

func (r *userRepository) ListWithFilters(ctx context.Context, page, limit int, filters map[string]string) ([]*entities.User, int, error) {
	// Validar entrada
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		return nil, 0, errors.New("limit must be greater than 0")
	}

	// Base de la consulta
	baseQuery := `FROM users WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	// Aplicar filtros
	if status, ok := filters["status"]; ok {
		// Validar valores permitidos para status (opcional)
		validStatuses := map[string]bool{"active": true, "inactive": true, "pending": true}
		if !validStatuses[status] {
			return nil, 0, fmt.Errorf("invalid status: %s", status)
		}
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	if search, ok := filters["search"]; ok {
		baseQuery += fmt.Sprintf(` AND (
            dni ILIKE $%d OR 
            email ILIKE $%d OR 
            nombres ILIKE $%d OR 
            apellido_paterno ILIKE $%d OR
            apellido_materno ILIKE $%d OR
            nombres_completos ILIKE $%d OR
            telefono ILIKE $%d OR
            departamento ILIKE $%d OR
            provincia ILIKE $%d OR
            distrito ILIKE $%d
        )`, argIndex, argIndex+1, argIndex+2, argIndex+3, argIndex+4, argIndex+5, argIndex+6, argIndex+7, argIndex+8, argIndex+9)
		for i := 0; i < 10; i++ {
			args = append(args, "%"+search+"%")
		}
		argIndex += 10
	}

	// Construir consultas
	countQuery := `SELECT COUNT(*) ` + baseQuery
	listQuery := `
        SELECT 
            id, dni, email, password, nombres, apellido_paterno, apellido_materno, nombres_completos,
            fecha_nacimiento, telefono, departamento, provincia, distrito, direccion_completa, avatar_url, 
            status, verified, last_login, created_at, updated_at
        ` + baseQuery + fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argIndex, argIndex+1)

	// Añadir limit y offset
	args = append(args, limit, (page-1)*limit)

	// Obtener total
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args[:argIndex-1]...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Ejecutar consulta con paginación
	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	// Procesar resultados
	var users []*entities.User
	for rows.Next() {
		var user entities.User
		var lastLogin sql.NullTime

		if err := rows.Scan(
			&user.ID,
			&user.DNI,
			&user.Email,
			&user.Password,
			&user.Nombres,
			&user.ApellidoPaterno,
			&user.ApellidoMaterno,
			&user.NombresCompletos,
			&user.FechaNacimiento,
			&user.Telefono,
			&user.Departamento,
			&user.Provincia,
			&user.Distrito,
			&user.DireccionCompleta,
			&user.AvatarURL,
			&user.Status,
			&user.Verified,
			&lastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating rows: %w", err)
	}

	return users, total, nil
}

// func (r *userRepository) ListWithAdvancedFilters(ctx context.Context, page, limit int, filters map[string]interface{}) ([]*entities.User, int, error) {
// 	// Base de la consulta
// 	baseQuery := `FROM users WHERE 1=1`
// 	args := []interface{}{}
// 	argIndex := 1

// 	// Aplicar filtros
// 	if status, ok := filters["status"].(string); ok && status != "" {
// 		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
// 		args = append(args, status)
// 		argIndex++
// 	}

// 	if search, ok := filters["search"].(string); ok && search != "" {
// 		baseQuery += fmt.Sprintf(` AND (
// 			dni ILIKE $%d OR 
// 			email ILIKE $%d OR 
// 			nombres ILIKE $%d OR 
// 			apellido_paterno ILIKE $%d OR
// 			apellido_materno ILIKE $%d OR
// 			telefono ILIKE $%d
// 		)`, argIndex, argIndex, argIndex, argIndex, argIndex, argIndex)
// 		args = append(args, "%"+search+"%")
// 		argIndex++
// 	}

// 	if ids, ok := filters["ids"].([]uuid.UUID); ok && len(ids) > 0 {
// 		// Usar librería pq para array de UUIDs
// 		baseQuery += fmt.Sprintf(" AND id = ANY($%d)", argIndex)
// 		args = append(args, pq.Array(ids))
// 		argIndex++
// 	}

// 	// Construir consultas
// 	countQuery := `SELECT COUNT(*) ` + baseQuery
// 	listQuery := `
// 		SELECT 
// 			id, dni, email, nombres, apellido_paterno, apellido_materno,
// 			nombres_completos, telefono, avatar_url, status, verified, 
// 			last_login, created_at, updated_at
// 		` + baseQuery + ` ORDER BY created_at DESC LIMIT $` + fmt.Sprintf("%d", argIndex) + ` OFFSET $` + fmt.Sprintf("%d", argIndex+1)

// 	// Añadir limit y offset
// 	args = append(args, limit, (page-1)*limit)

// 	// Obtener total
// 	var total int
// 	err := r.db.QueryRowContext(ctx, countQuery, args[:argIndex-1]...).Scan(&total)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	// Ejecutar consulta con paginación
// 	rows, err := r.db.QueryContext(ctx, listQuery, args...)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	defer rows.Close()

// 	var users []*entities.User
// 	for rows.Next() {
// 		var user entities.User
// 		var lastLogin sql.NullTime

// 		err := rows.Scan(
// 			&user.ID,
// 			&user.DNI,
// 			&user.Email,
// 			&user.Nombres,
// 			&user.ApellidoPaterno,
// 			&user.ApellidoMaterno,
// 			&user.NombresCompletos,
// 			&user.Telefono,
// 			&user.AvatarURL,
// 			&user.Status,
// 			&user.Verified,
// 			&lastLogin,
// 			&user.CreatedAt,
// 			&user.UpdatedAt,
// 		)
// 		if err != nil {
// 			return nil, 0, err
// 		}

// 		if lastLogin.Valid {
// 			user.LastLogin = &lastLogin.Time
// 		}

// 		users = append(users, &user)
// 	}

// 	if err = rows.Err(); err != nil {
// 		return nil, 0, err
// 	}

// 	return users, total, nil
// }

/*
  ***************************************************************************************
  Metodo: ListWithAdvancedFilters
  Objetivo: Listar usuarios con filtros avanzados y optimizados
  Fecha: 19-09-2025
  Descripcion: 
  Autor: 
  ***************************************************************************************
*/

func (r *userRepository) ListWithAdvancedFilters(ctx context.Context, params ListUsersParams) (ListUsersResult, error) {
	startTime := time.Now()
	
	// Validar parámetros
	if err := r.validateListParams(&params); err != nil {
		return ListUsersResult{}, err
	}

	// Construir query dinámica optimizada
	queryBuilder := r.newOptimizedQueryBuilder()
	query, args, metadata := queryBuilder.BuildListQuery(params)

	// Ejecutar query
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListUsersResult{}, fmt.Errorf("failed to execute optimized list query: %w", err)
	}
	defer rows.Close()

	// Procesar resultados
	users, hasNextPage, err := r.processUserRows(rows, params.Limit)
	if err != nil {
		return ListUsersResult{}, err
	}

	// Metadata de rendimiento
	metadata.ExecutionTime = time.Since(startTime)

	return ListUsersResult{
		Users:       users,
		HasNextPage: hasNextPage,
		Metadata:    metadata,
	}, nil
}

// ListWithTotalCount - Versión que incluye total count (más lenta)
func (r *userRepository) ListWithTotalCount(ctx context.Context, params ListUsersParams) (ListUsersResult, error) {
	startTime := time.Now()
	
	if err := r.validateListParams(&params); err != nil {
		return ListUsersResult{}, err
	}

	queryBuilder := r.newOptimizedQueryBuilder()
	query, args, metadata := queryBuilder.BuildListQueryWithTotal(params)
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListUsersResult{}, fmt.Errorf("failed to execute query with total: %w", err)
	}
	defer rows.Close()

	var users []*entities.User
	var totalCount int
	
	for rows.Next() {
		var user entities.User
		var lastLogin sql.NullTime
		var total int

		err := rows.Scan(
			&user.ID, &user.DNI, &user.Email, &user.Nombres, &user.ApellidoPaterno, &user.ApellidoMaterno,
			&user.NombresCompletos, &user.Telefono, &user.AvatarURL, &user.Status, &user.Verified,
			&lastLogin, &user.CreatedAt, &user.UpdatedAt, &total,
		)
		if err != nil {
			return ListUsersResult{}, err
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
		totalCount = total
	}

	hasNextPage := params.Offset+len(users) < totalCount
	metadata.ExecutionTime = time.Since(startTime)

	return ListUsersResult{
		Users:       users,
		HasNextPage: hasNextPage,
		TotalCount:  &totalCount,
		Metadata:    metadata,
	}, nil
}

// ================================================================
// QUERY BUILDER OPTIMIZADO
// ================================================================

type optimizedQueryBuilder struct {
	repo *userRepository
}

func (r *userRepository) newOptimizedQueryBuilder() *optimizedQueryBuilder {
	return &optimizedQueryBuilder{repo: r}
}

func (qb *optimizedQueryBuilder) BuildListQuery(params ListUsersParams) (string, []interface{}, *QueryMetadata) {
	var (
		queryParts []string
		args       []interface{}
		argIdx     = 1
		metadata   = &QueryMetadata{}
	)

	// Base query optimizada
	baseQuery := `
	SELECT 
		id, dni, email, nombres, apellido_paterno, apellido_materno,
		nombres_completos, telefono, avatar_url, status, verified, 
		last_login, created_at, updated_at
	FROM users
	WHERE 1=1`
	
	queryParts = append(queryParts, baseQuery)

	// Filtros optimizados (en orden de selectividad)
	if len(params.IDs) > 0 {
		queryParts = append(queryParts, fmt.Sprintf("AND id = ANY($%d)", argIdx))
		args = append(args, pq.Array(params.IDs))
		argIdx++
		metadata.IndexesUsed = append(metadata.IndexesUsed, "users_pkey")
	}

	if params.Status != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND status = $%d", argIdx))
		args = append(args, *params.Status)
		argIdx++
		metadata.IndexesUsed = append(metadata.IndexesUsed, "idx_users_status")
	}

	if params.Verified != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND verified = $%d", argIdx))
		args = append(args, *params.Verified)
		argIdx++
		metadata.IndexesUsed = append(metadata.IndexesUsed, "idx_users_verified")
	}

	// Filtros de ubicación
	if params.Departamento != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND departamento = $%d", argIdx))
		args = append(args, *params.Departamento)
		argIdx++
	}
	if params.Provincia != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND provincia = $%d", argIdx))
		args = append(args, *params.Provincia)
		argIdx++
	}
	if params.Distrito != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND distrito = $%d", argIdx))
		args = append(args, *params.Distrito)
		argIdx++
	}

	// Filtros de fecha
	if params.CreatedAfter != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND created_at >= $%d", argIdx))
		args = append(args, *params.CreatedAfter)
		argIdx++
	}
	if params.CreatedBefore != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND created_at <= $%d", argIdx))
		args = append(args, *params.CreatedBefore)
		argIdx++
	}
	if params.LastLoginAfter != nil {
		queryParts = append(queryParts, fmt.Sprintf("AND last_login >= $%d", argIdx))
		args = append(args, *params.LastLoginAfter)
		argIdx++
	}

	// Búsqueda de texto (al final para mejor rendimiento)
	if params.Search != nil && strings.TrimSpace(*params.Search) != "" {
		searchTerm := strings.TrimSpace(*params.Search)
		if len(searchTerm) > 2 {
			queryParts = append(queryParts, fmt.Sprintf(`
			AND to_tsvector('spanish',
				coalesce(nombres,'') || ' ' ||
				coalesce(apellido_paterno,'') || ' ' ||
				coalesce(apellido_materno,'') || ' ' ||
				coalesce(dni,'') || ' ' ||
				coalesce(email,'') || ' ' ||
				coalesce(telefono,'')
			) @@ plainto_tsquery('spanish', $%d)`, argIdx))
			args = append(args, searchTerm)
			argIdx++
			metadata.QueryUsedFTS = true
			metadata.IndexesUsed = append(metadata.IndexesUsed, "idx_users_search_gin")
		} else {
			queryParts = append(queryParts, fmt.Sprintf(`
			AND (dni ILIKE $%d OR email ILIKE $%d)`, argIdx, argIdx))
			args = append(args, "%"+searchTerm+"%", "%"+searchTerm+"%")
			argIdx++
		}
	}

	// Ordenamiento optimizado
	orderClause := qb.buildOptimizedOrderClause(params, metadata)
	queryParts = append(queryParts, orderClause)

	// Paginación con LIMIT+1 trick
	limitPlusOne := params.Limit + 1
	queryParts = append(queryParts, fmt.Sprintf("LIMIT $%d OFFSET $%d", argIdx, argIdx+1))
	args = append(args, limitPlusOne, params.Offset)

	finalQuery := strings.Join(queryParts, "\n")
	return finalQuery, args, metadata
}

func (qb *optimizedQueryBuilder) BuildListQueryWithTotal(params ListUsersParams) (string, []interface{}, *QueryMetadata) {
	query, args, metadata := qb.BuildListQuery(params)
	
	// Reemplazar SELECT para incluir COUNT() OVER()
	query = strings.Replace(query, 
		"created_at, updated_at\n\tFROM users", 
		"created_at, updated_at, COUNT(*) OVER() as total_count\n\tFROM users", 1)
	
	return query, args, metadata
}

func (qb *optimizedQueryBuilder) buildOptimizedOrderClause(params ListUsersParams, metadata *QueryMetadata) string {
	sortBy := "created_at"
	sortOrder := "DESC"

	if params.SortBy != nil {
		switch *params.SortBy {
		case "created_at", "last_login":
			sortBy = *params.SortBy
		case "relevance":
			if metadata.QueryUsedFTS {
				return `ORDER BY ts_rank(
					to_tsvector('spanish', 
						coalesce(nombres,'') || ' ' || 
						coalesce(apellido_paterno,'') || ' ' || 
						coalesce(apellido_materno,'') || ' ' || 
						coalesce(dni,'') || ' ' || 
						coalesce(email,'')
					), 
					plainto_tsquery('spanish', $3)
				) DESC, created_at DESC`
			}
		}
	}

	if params.SortOrder != nil && (*params.SortOrder == "asc" || *params.SortOrder == "ASC") {
		sortOrder = "ASC"
	}

	return fmt.Sprintf("ORDER BY %s %s", sortBy, sortOrder)
}

// ================================================================
// FUNCIONES DE APOYO
// ================================================================

func (r *userRepository) validateListParams(params *ListUsersParams) error {
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Limit > 100 {
		return fmt.Errorf("limit cannot exceed 100, got %d", params.Limit)
	}
	if params.Offset < 0 {
		params.Offset = 0
	}
	if len(params.IDs) > 1000 {
		return fmt.Errorf("too many IDs provided: %d (max 1000)", len(params.IDs))
	}

	if params.Status != nil {
		validStatuses := map[entities.UserStatus]bool{
			"ACTIVE": true, "INACTIVE": true, "SUSPENDED": true, "DELETED": true,
		}
		if !validStatuses[*params.Status] {
			return fmt.Errorf("invalid status: %s", *params.Status)
		}
	}

	if params.Search != nil {
		search := strings.TrimSpace(*params.Search)
		if len(search) > 100 {
			return fmt.Errorf("search term too long: %d characters (max 100)", len(search))
		}
		if len(search) == 0 {
			params.Search = nil
		}
	}

	return nil
}

func (r *userRepository) processUserRows(rows *sql.Rows, limit int) ([]*entities.User, bool, error) {
	var users []*entities.User
	
	for rows.Next() {
		var user entities.User
		var lastLogin sql.NullTime

		err := rows.Scan(
			&user.ID, &user.DNI, &user.Email, &user.Nombres, &user.ApellidoPaterno, &user.ApellidoMaterno,
			&user.NombresCompletos, &user.Telefono, &user.AvatarURL, &user.Status, &user.Verified,
			&lastLogin, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, false, fmt.Errorf("failed to scan user: %w", err)
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("error iterating rows: %w", err)
	}

	hasNextPage := len(users) > limit
	if hasNextPage {
		users = users[:limit]
	}

	return users, hasNextPage, nil
}
/*
  ***************************************************************************************
  Metodo: ListWithAdvancedFilters
  Objetivo: Listar usuarios con filtros avanzados y optimizados
  Fecha: 19-09-2025
  Descripcion:  TERMINA LA FUNCION
  Autor: 
  ***************************************************************************************
*/

// BeginTx inicia una nueva transacción
func (r *userRepository) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

// CommitTx confirma una transacción
func (r *userRepository) CommitTx(tx *sql.Tx) error {
	return tx.Commit()
}

// RollbackTx cancela una transacción
func (r *userRepository) RollbackTx(tx *sql.Tx) error {
	return tx.Rollback()
}

// FindByTelefono busca un usuario por su número de teléfono.
func (r *userRepository) FindByTelefono(ctx context.Context, telefono string) (*entities.User, error) {
	query := `
		SELECT 
			id, dni, email, password, nombres, apellido_paterno, apellido_materno,
			nombres_completos, fecha_nacimiento, telefono, departamento, provincia,
			distrito, direccion_completa, avatar_url, status, verified, last_login,
			created_at, updated_at
		FROM users
		WHERE telefono = $1
	`

	var user entities.User
	var lastLogin sql.NullTime

	err := r.db.QueryRowContext(ctx, query, telefono).Scan(
		&user.ID,
		&user.DNI,
		&user.Email,
		&user.Password,
		&user.Nombres,
		&user.ApellidoPaterno,
		&user.ApellidoMaterno,
		&user.NombresCompletos,
		&user.FechaNacimiento,
		&user.Telefono,
		&user.Departamento,
		&user.Provincia,
		&user.Distrito,
		&user.DireccionCompleta,
		&user.AvatarURL,
		&user.Status,
		&user.Verified,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
