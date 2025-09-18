package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"auth-microservice-go.v2/pkg/domain/entities"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ErrSessionNotFound se devuelve cuando una sesión no se encuentra en la base de datos.
var ErrSessionNotFound = errors.New("sesión no encontrada")

type sessionRepository struct {
	db *sqlx.DB
}

// NewSessionRepository crea una nueva instancia del repositorio de sesiones.
func NewSessionRepository(db *sqlx.DB) *sessionRepository {
	return &sessionRepository{
		db: db,
	}
}

// Create inserta una nueva sesión en la base de datos, soportando transacciones opcionales.
// Devuelve un error si la operación falla o si los datos de la sesión son inválidos.
func (r *sessionRepository) Create(ctx context.Context, session *entities.Session) error {
	if session == nil || session.ID == uuid.Nil || session.Token == "" || session.UserID == uuid.Nil {
		return errors.New("sesión inválida")
	}

	query := `
		INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	db := r.db

	_, err := db.ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.Token,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	)

	return err
}

// Update actualiza una sesión existente en la base de datos, soportando transacciones opcionales.
// Devuelve un error si la operación falla o si los datos de la sesión son inválidos.
func (r *sessionRepository) Update(ctx context.Context, session *entities.Session) error {
	if session == nil || session.ID == uuid.Nil || session.Token == "" {
		return errors.New("sesión inválida")
	}

	query := `
		UPDATE sessions
		SET token = $2, ip_address = $3, user_agent = $4, expires_at = $5, updated_at = $6
		WHERE id = $1
	`

	db := r.db

	_, err := db.ExecContext(
		ctx,
		query,
		session.ID,
		session.Token,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		time.Now(),
	)

	return err
}

// FindByID busca una sesión por su ID.
// Devuelve la sesión encontrada o un error si no se encuentra o falla la consulta.
func (r *sessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.Session, error) {
	if id == uuid.Nil {
		return nil, ErrSessionNotFound
	}

	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`

	var session entities.Session
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	return &session, nil
}

// FindByToken busca una sesión por su token.
// Devuelve la sesión encontrada o un error si no se encuentra o falla la consulta.
// func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*entities.Session, error) {
// 	if token == "" {
// 		return nil, ErrSessionNotFound
// 	}

// 	query := `
// 		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
// 		FROM sessions
// 		WHERE token = $1
// 	`

// 	var session entities.Session
// 	err := r.db.QueryRowContext(ctx, query, token).Scan(
// 		&session.ID,
// 		&session.UserID,
// 		&session.Token,
// 		&session.IPAddress,
// 		&session.UserAgent,
// 		&session.ExpiresAt,
// 		&session.CreatedAt,
// 		&session.UpdatedAt,
// 	)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			return nil, ErrSessionNotFound
// 		}
// 		return nil, err
// 	}

// 	return &session, nil
// }

// FindByUser busca todas las sesiones asociadas a un usuario por su ID.
// Devuelve una lista de sesiones o un error si falla la consulta.
func (r *sessionRepository) FindByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error) {
	if userID == uuid.Nil {
		return nil, errors.New("ID de usuario inválido")
	}

	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions
		WHERE user_id = $1
	`

	var sessions []*entities.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

// Delete elimina una sesión por su ID.
// Devuelve un error si la operación falla.
func (r *sessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("ID de sesión inválido")
	}

	query := `DELETE FROM sessions WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// DeleteAllForUser elimina todas las sesiones asociadas a un usuario por su ID.
// Devuelve un error si la operación falla.
func (r *sessionRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return errors.New("ID de usuario inválido")
	}

	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// CleanupExpiredSessions elimina todas las sesiones expiradas y retorna la cantidad eliminada.
func (r *sessionRepository) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rows, nil
}

// CountActiveSessions cuenta sesiones activas para un usuario
func (r *sessionRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW()`
	var count int
	err := r.db.GetContext(ctx, &count, query, userID)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetSessionsByIPAddress obtiene sesiones por dirección IP (para seguridad)
func (r *sessionRepository) GetSessionsByIPAddress(ctx context.Context, ipAddress string) ([]*entities.Session, error) {
	query := `SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at FROM sessions WHERE ip_address = $1`
	var sessions []*entities.Session
	err := r.db.SelectContext(ctx, &sessions, query, ipAddress)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// ============================================================================
// NUEVOS MÉTODOS CON SOPORTE DE TRANSACCIONES
// ============================================================================

// CreateTx crea una sesión dentro de una transacción
func (r *sessionRepository) CreateTx(ctx context.Context, session *entities.Session, tx *sql.Tx) error {
	query := `
        INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	// Si hay transacción, usarla; si no, usar conexión normal
	if tx != nil {
		_, err := tx.ExecContext(
			ctx,
			query,
			session.ID,
			session.UserID,
			session.Token,
			session.IPAddress,
			session.UserAgent,
			session.ExpiresAt,
			session.CreatedAt,
			session.UpdatedAt,
		)
		return err
	} else {
		return r.Create(ctx, session)
	}
}

// DeleteByUserIDTx elimina todas las sesiones de un usuario dentro de una transacción
func (r *sessionRepository) DeleteByUserIDTx(ctx context.Context, userID uuid.UUID, tx *sql.Tx) error {
	query := `DELETE FROM sessions WHERE user_id = $1`

	if tx != nil {
		_, err := tx.ExecContext(ctx, query, userID)
		return err
	} else {
		_, err := r.db.ExecContext(ctx, query, userID)
		return err
	}
}

// DeleteAllForUserTx es un alias para DeleteByUserIDTx (compatibilidad)
func (r *sessionRepository) DeleteAllForUserTx(ctx context.Context, userID uuid.UUID, tx *sql.Tx) error {
	return r.DeleteByUserIDTx(ctx, userID, tx)
}

// DeleteExpired elimina todas las sesiones expiradas hasta el momento actual.
func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}


// ============================================================================
// MÉTODOS NECESARIOS PARA EL LOGOUT
// ============================================================================

// FindByToken busca una sesión por su token
func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*entities.Session, error) {
	if token == "" {
		return nil, ErrSessionNotFound
	}

	var session entities.Session
	
	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions 
		WHERE token = $1 AND expires_at > NOW()
	`
	
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("error al buscar sesión por token: %v", err)
	}
	
	return &session, nil
}

// DeleteByToken elimina una sesión por su token
func (r *sessionRepository) DeleteByToken(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token vacío")
	}

	query := `DELETE FROM sessions WHERE token = $1`
	
	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("error al eliminar sesión por token: %v", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error al verificar filas afectadas: %v", err)
	}
	
	if rowsAffected == 0 {
		return ErrSessionNotFound
	}
	
	return nil
}

// DeleteAllByUserID elimina todas las sesiones de un usuario
func (r *sessionRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return errors.New("ID de usuario inválido")
	}

	query := `DELETE FROM sessions WHERE user_id = $1`
	
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("error al eliminar sesiones del usuario: %v", err)
	}
	
	return nil
}

// DeleteExpiredSessions elimina sesiones expiradas
func (r *sessionRepository) DeleteExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at <= NOW()`
	
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error al eliminar sesiones expiradas: %v", err)
	}
	
	rowsAffected, _ := result.RowsAffected()
	log.Printf("Sesiones expiradas eliminadas: %d", rowsAffected)
	
	return nil
}