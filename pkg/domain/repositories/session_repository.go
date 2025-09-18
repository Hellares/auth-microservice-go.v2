package repositories

import (
	"context"
	"database/sql"

	"auth-microservice-go.v2/pkg/domain/entities"
	"github.com/google/uuid"
)

type SessionRepository interface {
	Create(ctx context.Context, session *entities.Session) error
	Update(ctx context.Context, session *entities.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	// FindByToken(ctx context.Context, token string) (*entities.Session, error)
	FindByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error

	// NUEVOS MÉTODOS CON TRANSACCIONES
	CreateTx(ctx context.Context, session *entities.Session, tx *sql.Tx) error
	DeleteByUserIDTx(ctx context.Context, userID uuid.UUID, tx *sql.Tx) error
	DeleteAllForUserTx(ctx context.Context, userID uuid.UUID, tx *sql.Tx) error

	// ============================================================================
	// OPERACIONES DE LIMPIEZA Y MANTENIMIENTO
	// ============================================================================
	
	// CleanupExpiredSessions limpia sesiones expiradas automáticamente
	CleanupExpiredSessions(ctx context.Context) (int64, error)
	
	// CountActiveSessions cuenta sesiones activas para un usuario
	CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error)
	
	// GetSessionsByIPAddress obtiene sesiones por dirección IP (para seguridad)
	GetSessionsByIPAddress(ctx context.Context, ipAddress string) ([]*entities.Session, error)

    
    
    // Nuevos métodos para logout
	FindByToken(ctx context.Context, token string) (*entities.Session, error)
	DeleteByToken(ctx context.Context, token string) error
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error
}