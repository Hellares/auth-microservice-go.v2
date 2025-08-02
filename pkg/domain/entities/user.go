package entities

import (
	"time"
	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusInactive UserStatus = "INACTIVE"
	UserStatusBlocked  UserStatus = "BLOCKED"
)

type User struct {
	ID        		    uuid.UUID   `json:"id"`
	DNI	   			    string      `json:"dni"`
	Nombres   		    string      `json:"nombres"`
	ApellidoPaterno     string      `json:"apellido_paterno"`
	ApellidoMaterno     string      `json:"apellido_materno"`
	NombresCompletos 	string      `json:"nombres_completos"`
	FechaNacimiento 	time.Time   `json:"fecha_nacimiento"`
	Departamento   		string      `json:"departamento"`
	Provincia	   		string      `json:"provincia"`
	Distrito	   		string      `json:"distrito"`
	DireccionCompleta 	string      `json:"direccion_completa"`
	Email          		string      `json:"email"`
	Telefono       		string      `json:"telefono,omitempty"`
	Password 	  		string      `json:"-"`
	AvatarURL      		string      `json:"avatar_url,omitempty"`
	Status 	   			UserStatus  `json:"status"`
	Verified	   		bool        `json:"verified"`
	LastLogin	   		*time.Time  `json:"last_login,omitempty"`
	CreatedAt      		time.Time   `json:"createdAt"`
	UpdatedAt      		time.Time   `json:"updatedAt"`	

}