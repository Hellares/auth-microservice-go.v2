package repositories

import (
	"context"

	"github.com/google/uuid"
	"auth-microservice-go.v2/pkg/domain/entities"
)

type VerificationTokenRepository interface {
	Create(ctx context.Context, token *entities.VerificationToken) error
	FindByToken(ctx context.Context, token string) (*entities.VerificationToken, error)
	FindByUserAndType(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}