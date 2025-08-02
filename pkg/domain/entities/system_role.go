package entities

import (
    "time"
    "github.com/google/uuid"
)

type SystemRole struct {
    ID        uuid.UUID `json:"id"`
    UserID    uuid.UUID `json:"userId"`
    RoleName  string    `json:"roleName"`
    Active    bool      `json:"active"`
    CreatedAt time.Time `json:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt"`
}