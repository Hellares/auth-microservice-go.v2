// pkg/infrastructure/persistence/postgres/verification_token_repository.go
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

// ErrVerificationTokenNotFound se devuelve cuando un token de verificación no se encuentra.
var ErrVerificationTokenNotFound = errors.New("token de verificación no encontrado")

type verificationTokenRepository struct {
    db *sqlx.DB
}

// NewVerificationTokenRepository crea una nueva instancia del repositorio de tokens de verificación.
func NewVerificationTokenRepository(db *sqlx.DB) *verificationTokenRepository {
    return &verificationTokenRepository{
        db: db,
    }
}

// Create inserta un nuevo token de verificación en la base de datos.
// Devuelve un error si la operación falla o si los datos del token son inválidos.
func (r *verificationTokenRepository) Create(ctx context.Context, token *entities.VerificationToken) error {
    if token == nil || token.ID == uuid.Nil || token.UserID == uuid.Nil || token.Token == "" {
        return errors.New("token de verificación inválido")
    }

    query := `
        INSERT INTO verification_tokens (id, user_id, token, type, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `

    _, err := r.db.ExecContext(
        ctx,
        query,
        token.ID,
        token.UserID,
        token.Token,
        token.Type,
        token.ExpiresAt,
        token.CreatedAt,
    )

    return err
}

// FindByToken busca un token de verificación por su valor de token.
// Devuelve el token encontrado o un error si no se encuentra o falla la consulta.
func (r *verificationTokenRepository) FindByToken(ctx context.Context, token string) (*entities.VerificationToken, error) {
    if token == "" {
        return nil, ErrVerificationTokenNotFound
    }

    query := `
        SELECT id, user_id, token, type, expires_at, created_at
        FROM verification_tokens
        WHERE token = $1
    `

    var vt entities.VerificationToken
    err := r.db.QueryRowContext(ctx, query, token).Scan(
        &vt.ID,
        &vt.UserID,
        &vt.Token,
        &vt.Type,
        &vt.ExpiresAt,
        &vt.CreatedAt,
    )

    if err != nil {
        if err == sql.ErrNoRows {
            return nil, ErrVerificationTokenNotFound
        }
        return nil, err
    }

    return &vt, nil
}

// FindByUserAndType busca un token de verificación por usuario y tipo específico.
// Devuelve el token encontrado o un error si no se encuentra o falla la consulta.
func (r *verificationTokenRepository) FindByUserAndType(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error) {
    if userID == uuid.Nil || tokenType == "" {
        return nil, ErrVerificationTokenNotFound
    }

    query := `
        SELECT id, user_id, token, type, expires_at, created_at
        FROM verification_tokens
        WHERE user_id = $1 AND type = $2
        ORDER BY created_at DESC
        LIMIT 1
    `

    var vt entities.VerificationToken
    err := r.db.QueryRowContext(ctx, query, userID, tokenType).Scan(
        &vt.ID,
        &vt.UserID,
        &vt.Token,
        &vt.Type,
        &vt.ExpiresAt,
        &vt.CreatedAt,
    )

    if err != nil {
        if err == sql.ErrNoRows {
            return nil, ErrVerificationTokenNotFound
        }
        return nil, err
    }

    return &vt, nil
}

// FindActiveByUserAndType busca un token activo (no expirado) por usuario y tipo.
// Devuelve el token encontrado o un error si no se encuentra o falla la consulta.
func (r *verificationTokenRepository) FindActiveByUserAndType(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error) {
    if userID == uuid.Nil || tokenType == "" {
        return nil, ErrVerificationTokenNotFound
    }

    query := `
        SELECT id, user_id, token, type, expires_at, created_at
        FROM verification_tokens
        WHERE user_id = $1 AND type = $2 AND expires_at > $3
        ORDER BY created_at DESC
        LIMIT 1
    `

    var vt entities.VerificationToken
    err := r.db.QueryRowContext(ctx, query, userID, tokenType, time.Now()).Scan(
        &vt.ID,
        &vt.UserID,
        &vt.Token,
        &vt.Type,
        &vt.ExpiresAt,
        &vt.CreatedAt,
    )

    if err != nil {
        if err == sql.ErrNoRows {
            return nil, ErrVerificationTokenNotFound
        }
        return nil, err
    }

    return &vt, nil
}

// Delete elimina un token de verificación por su ID.
// Devuelve un error si la operación falla.
func (r *verificationTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
    if id == uuid.Nil {
        return errors.New("ID de token inválido")
    }

    query := `DELETE FROM verification_tokens WHERE id = $1`
    _, err := r.db.ExecContext(ctx, query, id)
    return err
}

// DeleteExpired elimina todos los tokens de verificación expirados.
// Devuelve un error si la operación falla.
func (r *verificationTokenRepository) DeleteExpired(ctx context.Context) error {
    query := `DELETE FROM verification_tokens WHERE expires_at < $1`
    _, err := r.db.ExecContext(ctx, query, time.Now())
    return err
}

// DeleteByUserAndType elimina todos los tokens de un usuario para un tipo específico.
// Útil para limpiar tokens anteriores antes de crear uno nuevo.
func (r *verificationTokenRepository) DeleteByUserAndType(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) error {
    if userID == uuid.Nil || tokenType == "" {
        return errors.New("parámetros inválidos")
    }

    query := `DELETE FROM verification_tokens WHERE user_id = $1 AND type = $2`
    _, err := r.db.ExecContext(ctx, query, userID, tokenType)
    return err
}