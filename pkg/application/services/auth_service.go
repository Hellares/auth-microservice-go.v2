package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"auth-microservice-go.v2/pkg/domain/entities"
	"auth-microservice-go.v2/pkg/infrastructure/auth"
)

// AuthService define la interfaz del servicio de autenticación
type AuthService interface {
	// Casos de uso básicos de autenticación
	Register(ctx context.Context, dni, email, password, nombres, apellidoPaterno, apellidoMaterno, nombresCompletos string, fechaNacimiento time.Time, telefono, departamento, provincia, distrito, direccionCompleta string) (*entities.User, error)
	Login(ctx context.Context, dni, password string) (string, error)
	VerifyToken(ctx context.Context, token string) (*auth.TokenClaims, error)

	
	// Gestión de usuarios
	GetUserByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetUserByDNI(ctx context.Context, dni string) (*entities.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entities.User, error)
	FindUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error)
	
	// Gestión de contraseñas
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	RequestPasswordReset(ctx context.Context, email string) (*entities.VerificationToken, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	
	// Verificación de email
	CreateVerificationToken(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error)
	VerifyEmail(ctx context.Context, token string) error
	
	// Gestión de roles y permisos
	GetUserRoles(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error)
	HasPermission(ctx context.Context, userID, empresaID uuid.UUID, permissionName string) (bool, error)
	HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	GetPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error)
	
	// Gestión de empresas y roles
	CreateEmpresaAdmin(ctx context.Context, user *entities.User, empresaID uuid.UUID) error
	AddUserToEmpresa(ctx context.Context, userID, empresaID, roleID uuid.UUID) error
	AddClientToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error
	GetUserEmpresas(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	
	// Casos de uso multi-empresa
	LoginMultiempresa(ctx context.Context, dni, password string) (*entities.User, string, error)
	GenerateTokenWithEmpresa(ctx context.Context, userID, empresaID uuid.UUID) (string, error)
	UserBelongsToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) (bool, error)
	
	// Búsquedas y listados
	GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, roleFilter string) ([]*UserWithRoles, int, error)
	ListAllUsers(ctx context.Context, page, limit int, filters map[string]string) ([]*UserInfo, int, error)
	
	// Gestión de roles específicos
	GetRoleByName(ctx context.Context, name string) (*entities.Role, error)
	AssignEmpresaAdmin(ctx context.Context, userID, empresaID uuid.UUID) error

	GetUserEmpresasWithRoles(ctx context.Context, userID uuid.UUID) ([]EmpresaWithRole, error)
	ListUsersInEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, filters map[string]string) ([]*UserInfo, int, error)



	GetUserEmpresasWithRolesOptimized(ctx context.Context, userID uuid.UUID) ([]*entities.EmpresaConRol, error)
}

// Estructuras auxiliares para respuestas

// UserWithRoles combina información de usuario con sus roles
type UserWithRoles struct {
	ID                uuid.UUID           `json:"id"`
	DNI               string              `json:"dni"`
	Email             string              `json:"email"`
	Nombres           string              `json:"nombres"`
	ApellidoPaterno   string              `json:"apellido_paterno"`
	ApellidoMaterno   string              `json:"apellido_materno"`
	NombresCompletos  string              `json:"nombres_completos"`
	Telefono          string              `json:"telefono,omitempty"`
	Status            entities.UserStatus `json:"status"`
	Verified          bool                `json:"verified"`
	CreatedAt         time.Time           `json:"createdAt"`
	UpdatedAt         time.Time           `json:"updatedAt"`
	Roles             []RoleSimple        `json:"roles"`
}

// UserInfo información completa de usuario con empresas
type UserInfo struct {
	ID                uuid.UUID           `json:"id"`
	DNI               string              `json:"dni"`
	Email             string              `json:"email"`
	Nombres           string              `json:"nombres"`
	ApellidoPaterno   string              `json:"apellido_paterno"`
	ApellidoMaterno   string              `json:"apellido_materno"`
	NombresCompletos  string              `json:"nombres_completos"`
	Telefono          string              `json:"telefono,omitempty"`
	Status            entities.UserStatus `json:"status"`
	Verified          bool                `json:"verified"`
	CreatedAt         time.Time           `json:"createdAt"`
	UpdatedAt         time.Time           `json:"updatedAt"`
	Empresas          []EmpresaInfo       `json:"empresas,omitempty"`
	Roles             []RoleSimple        `json:"roles,omitempty"`
}

// RoleSimple información básica de rol
type RoleSimple struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
}

// EmpresaInfo información de empresa con rol
type EmpresaInfo struct {
	ID   uuid.UUID `json:"id"`
	Role string    `json:"role"`
}

// EmpresaWithRole información completa de empresa con rol y permisos
type EmpresaWithRole struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
}