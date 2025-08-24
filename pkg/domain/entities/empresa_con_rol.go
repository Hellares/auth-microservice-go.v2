package entities

import (
    "github.com/google/uuid"
)

// EmpresaConRol representa una empresa con los roles del usuario
type EmpresaConRol struct {
    EmpresaID uuid.UUID `json:"empresaId"`
    Roles     []string  `json:"roles"`
}

// EmpresaWithRole mantener tu estructura existente para casos completos
type EmpresaWithRole struct {
    ID          uuid.UUID `json:"id"`
    Name        string    `json:"name"`
    Role        string    `json:"role"`
    Permissions []string  `json:"permissions"`
}