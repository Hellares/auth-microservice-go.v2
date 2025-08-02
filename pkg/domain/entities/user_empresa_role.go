package entities

import (
	"time"

	"github.com/google/uuid"
)

type UserEmpresaRole struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"userId"`
	EmpresaID uuid.UUID `json:"empresaId"`
	RoleID    uuid.UUID `json:"roleId"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	
	// Relaciones
	User *User `json:"user,omitempty"`
	Role *Role `json:"role,omitempty"`
}