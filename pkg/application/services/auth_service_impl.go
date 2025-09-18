package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"auth-microservice-go.v2/pkg/application/ports"
	"auth-microservice-go.v2/pkg/domain/entities"
	"auth-microservice-go.v2/pkg/domain/repositories"
	"auth-microservice-go.v2/pkg/infrastructure/auth"
)

// authServiceImpl implementa la interfaz AuthService
type authServiceImpl struct {
	userRepo              repositories.UserRepository
	roleRepo              repositories.RoleRepository
	permissionRepo        repositories.PermissionRepository
	userEmpresaRoleRepo   repositories.UserEmpresaRoleRepository
	verificationTokenRepo repositories.VerificationTokenRepository
	sessionRepo           repositories.SessionRepository
	systemRoleRepo        repositories.SystemRoleRepository
	jwtService            *auth.JWTService
	tokenExpiration       time.Duration
	emailSender           ports.EmailSender
	db                    *sql.DB // Nueva dependencia
}

// NewAuthService crea una nueva instancia del servicio de autenticación
func NewAuthService(
	userRepo repositories.UserRepository,
	roleRepo repositories.RoleRepository,
	permissionRepo repositories.PermissionRepository,
	userEmpresaRoleRepo repositories.UserEmpresaRoleRepository,
	verificationTokenRepo repositories.VerificationTokenRepository,
	sessionRepo repositories.SessionRepository,
	systemRoleRepo repositories.SystemRoleRepository,
	jwtSecret string,
	tokenExpiration time.Duration,
	emailSender ports.EmailSender,
	db *sql.DB,
) AuthService {
	jwtService := auth.NewJWTService(jwtSecret, tokenExpiration)

	return &authServiceImpl{
		userRepo:              userRepo,
		roleRepo:              roleRepo,
		permissionRepo:        permissionRepo,
		userEmpresaRoleRepo:   userEmpresaRoleRepo,
		verificationTokenRepo: verificationTokenRepo,
		sessionRepo:           sessionRepo,
		systemRoleRepo:        systemRoleRepo,
		jwtService:            jwtService,
		tokenExpiration:       tokenExpiration,
		emailSender:           emailSender,
		db:                 db,
	}
}

// Register registra un nuevo usuario con información completa
func (s *authServiceImpl) Register(ctx context.Context, dni, email, password, nombres, apellidoPaterno, apellidoMaterno, nombresCompletos string, fechaNacimiento time.Time, telefono, departamento, provincia, distrito, direccionCompleta string) (*entities.User, error) {
	// Verificar si el DNI ya está registrado
	existingUser, err := s.userRepo.FindByDNI(ctx, dni)
	if err == nil && existingUser != nil {
		return nil, errors.New("el DNI ya está registrado")
	}

	// Verificar si el email ya está registrado
	existingUser, err = s.userRepo.FindByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, errors.New("el email ya está registrado")
	}

	// Hash de la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &entities.User{
		ID:                uuid.New(),
		DNI:               dni,
		Email:             email,
		Password:          string(hashedPassword),
		Nombres:           nombres,
		ApellidoPaterno:   apellidoPaterno,
		ApellidoMaterno:   apellidoMaterno,
		NombresCompletos:  nombresCompletos, // Viene de la API externa
		FechaNacimiento:   fechaNacimiento,
		Telefono:          telefono,
		Departamento:      departamento,
		Provincia:         provincia,
		Distrito:          distrito,
		DireccionCompleta: direccionCompleta,
		Status:            entities.UserStatusActive,
		Verified:          false,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Generar token de verificación de email
	verificationToken, err := s.CreateVerificationToken(ctx, user.ID, entities.TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}

	// Enviar email de verificación
	if err := s.emailSender.SendVerificationEmail(user, verificationToken.Token); err != nil {
		return nil, err
	}

	return user, nil
}

// Login autentica a un usuario
func (s *authServiceImpl) Login(ctx context.Context, dni, password string) (string, error) {
	// Buscar usuario por DNI
	user, err := s.userRepo.FindByDNI(ctx, dni)
	if err != nil {
		return "", errors.New("credenciales inválidas")
	}

	// Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("credenciales inválidas")
	}

	// Crear claims para el token JWT
	claims := &auth.TokenClaims{
		UserID: user.ID.String(),
		DNI:    user.DNI,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiration)),
		},
	}

	// Generar token JWT
	token, err := s.jwtService.GenerateToken(claims)
	if err != nil {
		return "", fmt.Errorf("error al generar el token: %v", err)
	}

	// Crear sesión
	session := &entities.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(s.tokenExpiration),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session ); err != nil {
		return "", fmt.Errorf("error al crear la sesión: %v", err)
	}

	// Actualizar último login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		log.Printf("Error actualizando último login: %v", err)
	}

	return token, nil
}


func (s *authServiceImpl) VerifyToken(ctx context.Context, tokenString string) (*auth.TokenClaims, error) {
    // Verificar si el token existe en la base de datos
    session, err := s.sessionRepo.FindByToken(ctx, tokenString)
    if err != nil || session == nil || time.Now().After(session.ExpiresAt) {
        return nil, errors.New("token inválido o expirado")
    }

    // Intentar validar el token
    claims, err := s.jwtService.ValidateToken(tokenString)
    if err != nil {
        return nil, errors.New("token inválido")
    }

    return claims, nil
}


//! Implementado Logout invalida la sesión actual del usuario
func (s *authServiceImpl) Logout(ctx context.Context, token string) error {
    // Validar token JWT
    claims, err := s.jwtService.ValidateToken(token)
    if err != nil {
        return fmt.Errorf("token inválido: %v", err)
    }

    // Parsear userID
    userID, err := uuid.Parse(claims.UserID)
    if err != nil {
        return fmt.Errorf("ID de usuario inválido en token: %v", err)
    }

    // Buscar sesión por token
    session, err := s.sessionRepo.FindByToken(ctx, token)
    if err != nil {
        if strings.Contains(err.Error(), "no encontrada") {
            return fmt.Errorf("sesión no encontrada")
        }
        return fmt.Errorf("error al buscar sesión: %v", err)
    }

    // Verificar propiedad de la sesión
    if session.UserID != userID {
        return fmt.Errorf("sesión no pertenece al usuario")
    }

    // Eliminar sesión
    if err := s.sessionRepo.DeleteByToken(ctx, token); err != nil {
        return fmt.Errorf("error al cerrar sesión: %v", err)
    }

    return nil
}

// LogoutAllSessions cierra todas las sesiones del usuario
func (s *authServiceImpl) LogoutAllSessions(ctx context.Context, userID uuid.UUID) error {
    if err := s.sessionRepo.DeleteAllByUserID(ctx, userID); err != nil {
        return fmt.Errorf("error al cerrar todas las sesiones: %v", err)
    }
    
    return nil
}



// GetUserByID obtiene un usuario por su ID
func (s *authServiceImpl) GetUserByID(ctx context.Context, id uuid.UUID) (*entities.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

// GetUserByDNI obtiene un usuario por su DNI
func (s *authServiceImpl) GetUserByDNI(ctx context.Context, dni string) (*entities.User, error) {
	return s.userRepo.FindByDNI(ctx, dni)
}

// GetUserByEmail obtiene un usuario por su email
func (s *authServiceImpl) GetUserByEmail(ctx context.Context, email string) (*entities.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

// FindUserByIdentifier busca usuario por DNI, email o teléfono
func (s *authServiceImpl) FindUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error) {
	return s.userRepo.FindByIdentifier(ctx, identifier)
}

// ChangePassword cambia la contraseña de un usuario
func (s *authServiceImpl) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verificar contraseña actual
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return errors.New("contraseña actual incorrecta")
	}

	// Hash de la nueva contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	//USAR SIN TRANSACCIÓN (nil)
	return s.userRepo.UpdatePassword(ctx, userID, string(hashedPassword), nil)
}

// RequestPasswordReset solicita un reseteo de contraseña
func (s *authServiceImpl) RequestPasswordReset(ctx context.Context, email string) (*entities.VerificationToken, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("usuario no encontrado")
	}

	// Eliminar tokens de reseteo anteriores
	existingToken, err := s.verificationTokenRepo.FindByUserAndType(ctx, user.ID, entities.TokenTypePasswordReset)
	if err == nil && existingToken != nil {
		if err := s.verificationTokenRepo.Delete(ctx, existingToken.ID); err != nil {
			return nil, err
		}
	}

	// Crear nuevo token de reseteo
	token, err := s.CreateVerificationToken(ctx, user.ID, entities.TokenTypePasswordReset)
	if err != nil {
		return nil, err
	}

	// Enviar email con el token
	if err := s.emailSender.SendPasswordResetEmail(user, token.Token); err != nil {
		return nil, err
	}

	return token, nil
}


// ResetPassword - Versión con transacción (más segura)
func (s *authServiceImpl) ResetPassword(ctx context.Context, token, newPassword string) error {
    verificationToken, err := s.verificationTokenRepo.FindByToken(ctx, token)
    if err != nil {
        return errors.New("token inválido")
    }

    if verificationToken.Type != entities.TokenTypePasswordReset {
        return errors.New("tipo de token incorrecto")
    }

    if time.Now().After(verificationToken.ExpiresAt) {
        return errors.New("token expirado")
    }

    // Hash de la nueva contraseña
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    // ✅ USAR CON TRANSACCIÓN para operación atómica
    tx, err := s.userRepo.BeginTx(ctx)
    if err != nil {
        return fmt.Errorf("error al iniciar transacción: %v", err)
    }
    defer func() {
        if err != nil {
            s.userRepo.RollbackTx(tx)
        }
    }()

    // Actualizar contraseña dentro de la transacción
    if err = s.userRepo.UpdatePassword(ctx, verificationToken.UserID, string(hashedPassword), tx); err != nil {
        return fmt.Errorf("error al actualizar contraseña: %v", err)
    }

    // !Eliminar token usado (necesitarías actualizar este método también para soportar tx)
    if err = s.verificationTokenRepo.Delete(ctx, verificationToken.ID); err != nil {
        return fmt.Errorf("error al eliminar token: %v", err)
    }

    // Confirmar transacción
    if err = s.userRepo.CommitTx(tx); err != nil {
        return fmt.Errorf("error al confirmar transacción: %v", err)
    }

    return nil
}



// CreateVerificationToken crea un token de verificación para un usuario
func (s *authServiceImpl) CreateVerificationToken(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error) {
	// Generar token aleatorio
	tokenUUID := uuid.New()
	token := tokenUUID.String()

	// Definir expiración (24 horas para verificación de email, 1 hora para reseteo de contraseña)
	var expiresAt time.Time
	if tokenType == entities.TokenTypeEmailVerification {
		expiresAt = time.Now().Add(24 * time.Hour)
	} else {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	verificationToken := &entities.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     token,
		Type:      tokenType,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return nil, err
	}

	return verificationToken, nil
}

// VerifyEmail verifica el email de un usuario usando un token
func (s *authServiceImpl) VerifyEmail(ctx context.Context, token string) error {
	verificationToken, err := s.verificationTokenRepo.FindByToken(ctx, token)
	if err != nil {
		return errors.New("token inválido")
	}

	if verificationToken.Type != entities.TokenTypeEmailVerification {
		return errors.New("tipo de token incorrecto")
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return errors.New("token expirado")
	}

	// Marcar email como verificado
	if err := s.userRepo.VerifyEmail(ctx, verificationToken.UserID); err != nil {
		return err
	}

	// Eliminar token usado
	return s.verificationTokenRepo.Delete(ctx, verificationToken.ID)
}

// GetUserRoles obtiene los roles de un usuario en una empresa
func (s *authServiceImpl) GetUserRoles(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error) {
	return s.roleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
}


// HasPermission verifica si un usuario tiene un permiso específico en una empresa
func (s *authServiceImpl) HasPermission(ctx context.Context, userID, empresaID uuid.UUID, permissionName string) (bool, error) {
    // Primero, verificar si es un rol de sistema
    if permissionName == "SUPER_ADMIN" || permissionName == "SYSTEM_ADMIN" {
        return s.HasSystemRole(ctx, userID, permissionName)
    }

    // Si no hay empresa especificada y no es un rol de sistema, no tiene permiso
    if empresaID == uuid.Nil {
        return false, nil
    }

    // Log para debugging
    log.Printf("Verificando permiso %s para usuario %s en empresa %s", permissionName, userID, empresaID)

    // Consulta optimizada para verificar permisos
    permissions, err := s.userEmpresaRoleRepo.FindPermissionsByUserAndEmpresa(ctx, userID, empresaID)
    if err != nil {
        log.Printf("Error obteniendo permisos: %v", err)
        return false, err
    }

    // Verificar si el permiso está presente o si el nombre del rol coincide
    for _, perm := range permissions {
        if perm == permissionName {
            log.Printf("Usuario tiene el permiso %s", permissionName)
            return true, nil
        }
        // Verificar si el nombre del rol coincide con el permiso solicitado
        role, err := s.roleRepo.FindByName(ctx, perm)
        if err == nil && role != nil && role.Name == permissionName {
            log.Printf("Usuario tiene el rol %s", permissionName)
            return true, nil
        }
    }

    log.Printf("Usuario no tiene el permiso %s", permissionName)
    return false, nil
}

// HasSystemRole verifica si un usuario tiene un rol de sistema
func (s *authServiceImpl) HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return s.systemRoleRepo.HasSystemRole(ctx, userID, roleName)
}

// GetPermissionsByRole obtiene los permisos de un rol específico
func (s *authServiceImpl) GetPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error) {
	return s.permissionRepo.FindByRole(ctx, roleID)
}

// CreateEmpresaAdmin crea un administrador para una empresa
func (s *authServiceImpl) CreateEmpresaAdmin(ctx context.Context, user *entities.User, empresaID uuid.UUID) error {
	// Buscar el rol de administrador de empresa
	adminRole, err := s.roleRepo.FindByName(ctx, "EMPRESA_ADMIN")
	if err != nil {
		return err
	}

	// Asignar rol de administrador al usuario para la empresa
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    user.ID,
		EmpresaID: empresaID,
		RoleID:    adminRole.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// AddUserToEmpresa añade un usuario a una empresa con un rol específico
func (s *authServiceImpl) AddUserToEmpresa(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	// Verificar que el usuario existe
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verificar que el rol existe
	role, err := s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Verificar si ya existe esta relación
	existingRoles, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err == nil && len(existingRoles) > 0 {
		for _, existing := range existingRoles {
			if existing.RoleID == roleID {
				return errors.New("el usuario ya tiene este rol en la empresa")
			}
		}
	}

	// Crear la relación usuario-empresa-rol
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    user.ID,
		EmpresaID: empresaID,
		RoleID:    role.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// AddClientToEmpresa añade un usuario como cliente a una empresa
func (s *authServiceImpl) AddClientToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error {
	// Buscar rol de cliente
	clienteRole, err := s.roleRepo.FindByName(ctx, "CLIENTE")
	if err != nil {
		return errors.New("rol de cliente no encontrado")
	}

	// Verificar si ya existe esta relación
	existingRoles, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err == nil && len(existingRoles) > 0 {
		for _, existing := range existingRoles {
			if existing.RoleID == clienteRole.ID {
				// Si ya existe pero está inactivo, activarlo
				if !existing.Active {
					existing.Active = true
					existing.UpdatedAt = time.Now()
					return s.userEmpresaRoleRepo.Update(ctx, existing)
				}
				return errors.New("el usuario ya es cliente de esta empresa")
			}
		}
	}

	// Crear nueva relación
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    userID,
		EmpresaID: empresaID,
		RoleID:    clienteRole.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// GetUserEmpresas obtiene las empresas asociadas a un usuario
func (s *authServiceImpl) GetUserEmpresas(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	// Verificar que el usuario existe
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, errors.New("usuario no encontrado")
	}

	// Obtener las empresas asociadas al usuario
	return s.userEmpresaRoleRepo.FindEmpresasByUserID(ctx, userID)
}

func (s *authServiceImpl) LoginMultiempresa(ctx context.Context, dni, password string) (*entities.User, string, error) {
    // Buscar usuario por DNI
    user, err := s.userRepo.FindByDNI(ctx, dni)
    if err != nil {
        return nil, "", errors.New("credenciales inválidas")
    }

    // Verificar contraseña
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
        return nil, "", errors.New("credenciales inválidas")
    }

    // ✅ INICIAR TRANSACCIÓN
    tx, err := s.userRepo.BeginTx(ctx)
    if err != nil {
        return nil, "", fmt.Errorf("error al iniciar transacción: %v", err)
    }
    defer func() {
        if err != nil {
            s.userRepo.RollbackTx(tx)
        }
    }()

    // ✅ INVALIDAR SESIONES ANTIGUAS DENTRO DE LA TRANSACCIÓN
    if err := s.sessionRepo.DeleteByUserIDTx(ctx, user.ID, tx); err != nil {
        return nil, "", fmt.Errorf("error al invalidar sesiones antiguas: %v", err)
    }

    // Crear claims para el token JWT
    claims := &auth.TokenClaims{
        UserID: user.ID.String(),
        DNI:    user.DNI,
        Email:  user.Email,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiration)),
        },
    }

    // Generar token JWT
    token, err := s.jwtService.GenerateToken(claims)
    if err != nil {
        return nil, "", fmt.Errorf("error al generar el token: %v", err)
    }

    // ✅ CREAR SESIÓN DENTRO DE LA TRANSACCIÓN
    session := &entities.Session{
        ID:        uuid.New(),
        UserID:    user.ID,
        Token:     token,
        ExpiresAt: time.Now().Add(s.tokenExpiration),
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }

    if err := s.sessionRepo.CreateTx(ctx, session, tx); err != nil {
        return nil, "", fmt.Errorf("error al crear la sesión: %v", err)
    }

    // Actualizar último login (si implementas UpdateLastLoginTx)
    if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
        log.Printf("Error actualizando último login: %v", err)
        // No fallar por esto, solo registrar
    }

    // ✅ CONFIRMAR TRANSACCIÓN
    if err = s.userRepo.CommitTx(tx); err != nil {
        return nil, "", fmt.Errorf("error al confirmar transacción: %v", err)
    }

    return user, token, nil
}


// GenerateTokenWithEmpresa genera un token específico para una empresa
func (s *authServiceImpl) GenerateTokenWithEmpresa(ctx context.Context, userID, empresaID uuid.UUID) (string, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return "", err
	}

	// Crear claims con empresa específica
	claims := &auth.TokenClaimsWithEmpresa{
		UserID:    user.ID.String(),
		DNI:       user.DNI,
		Email:     user.Email,
		EmpresaID: empresaID.String(), // Agregar empresa al token
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiration)),
		},
	}

	return s.jwtService.GenerateTokenWithEmpresa(claims)
}

// UserBelongsToEmpresa verifica si un usuario pertenece a una empresa
func (s *authServiceImpl) UserBelongsToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) (bool, error) {
	roles, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err != nil {
		return false, err
	}

	// Verificar si tiene al menos un rol activo
	for _, role := range roles {
		if role.Active {
			return true, nil
		}
	}

	return false, nil
}

// GetUsersByEmpresa obtiene usuarios de una empresa con paginación
func (s *authServiceImpl) GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, roleFilter string) ([]*UserWithRoles, int, error) {
	// Obtener IDs de usuarios que pertenecen a esta empresa
	userIDs, err := s.userEmpresaRoleRepo.GetUsersByEmpresa(ctx, empresaID, roleFilter)
	if err != nil {
		return nil, 0, err
	}

	if len(userIDs) == 0 {
		return []*UserWithRoles{}, 0, nil
	}

	// Obtener información completa de los usuarios
	users, total, err := s.userRepo.FindByIDs(ctx, userIDs, page, limit)
	if err != nil {
		return nil, 0, err
	}

	// Convertir a UserWithRoles e incluir los roles
	usersWithRoles := make([]*UserWithRoles, len(users))
	for i, user := range users {
		roles, err := s.GetUserRoles(ctx, user.ID, empresaID)
		if err != nil {
			log.Printf("Error obteniendo roles para usuario %s: %v", user.ID, err)
			roles = []*entities.Role{}
		}

		// Convertir roles a RoleSimple
		simpleRoles := make([]RoleSimple, len(roles))
		for j, role := range roles {
			simpleRoles[j] = RoleSimple{
				ID:          role.ID,
				Name:        role.Name,
				Description: role.Description,
			}
		}

		usersWithRoles[i] = &UserWithRoles{
			ID:              user.ID,
			DNI:             user.DNI,
			Email:           user.Email,
			Nombres:         user.Nombres,
			ApellidoPaterno: user.ApellidoPaterno,
			ApellidoMaterno: user.ApellidoMaterno,
			NombresCompletos: user.NombresCompletos,
			Telefono:        user.Telefono,
			Status:          user.Status,
			Verified:        user.Verified,
			CreatedAt:       user.CreatedAt,
			UpdatedAt:       user.UpdatedAt,
			Roles:           simpleRoles,
		}
	}

	return usersWithRoles, total, nil
}

// ListAllUsers lista todos los usuarios del sistema (solo SUPER_ADMIN)
func (s *authServiceImpl) ListAllUsers(ctx context.Context, page, limit int, filters map[string]string) ([]*UserInfo, int, error) {
	// Obtener usuarios con paginación y filtros
	users, total, err := s.userRepo.ListWithFilters(ctx, page, limit, filters)
	if err != nil {
		return nil, 0, err
	}

	userInfos := make([]*UserInfo, len(users))

	for i, user := range users {
		// Para cada usuario, obtener sus empresas y roles
		empresaRoles, err := s.userEmpresaRoleRepo.FindByUserID(ctx, user.ID)
		if err != nil {
			log.Printf("Error obteniendo empresas para usuario %s: %v", user.ID, err)
			empresaRoles = []*entities.UserEmpresaRole{}
		}

		// Mapa para agrupar por empresa (para evitar duplicados)
		empresasMap := make(map[uuid.UUID]string)

		for _, er := range empresaRoles {
			// Obtener nombre del rol
			role, err := s.roleRepo.FindByID(ctx, er.RoleID)
			if err != nil {
				log.Printf("Error obteniendo rol %s: %v", er.RoleID, err)
				continue
			}

			// Si ya existe esta empresa, verificar si el rol actual tiene mayor prioridad
			if existingRole, found := empresasMap[er.EmpresaID]; found {
				if isPriorityRole(role.Name) && !isPriorityRole(existingRole) {
					empresasMap[er.EmpresaID] = role.Name
				}
			} else {
				empresasMap[er.EmpresaID] = role.Name
			}
		}

		// Convertir mapa a slice
		empresas := make([]EmpresaInfo, 0, len(empresasMap))
		for empresaID, roleName := range empresasMap {
			empresas = append(empresas, EmpresaInfo{
				ID:   empresaID,
				Role: roleName,
			})
		}

		// Crear UserInfo
		userInfos[i] = &UserInfo{
			ID:               user.ID,
			DNI:              user.DNI,
			Email:            user.Email,
			Nombres:          user.Nombres,
			ApellidoPaterno:  user.ApellidoPaterno,
			ApellidoMaterno:  user.ApellidoMaterno,
			NombresCompletos: user.NombresCompletos,
			Telefono:         user.Telefono,
			Status:           user.Status,
			Verified:         user.Verified,
			CreatedAt:        user.CreatedAt,
			UpdatedAt:        user.UpdatedAt,
			Empresas:         empresas,
		}
	}

	return userInfos, total, nil
}



// GetRoleByName obtiene un rol por su nombre
func (s *authServiceImpl) GetRoleByName(ctx context.Context, name string) (*entities.Role, error) {
	return s.roleRepo.FindByName(ctx, name)
}

// AssignEmpresaAdmin asigna rol de administrador de empresa a un usuario
func (s *authServiceImpl) AssignEmpresaAdmin(ctx context.Context, userID, empresaID uuid.UUID) error {
	// Buscar el rol de administrador de empresa
	adminRole, err := s.roleRepo.FindByName(ctx, "EMPRESA_ADMIN")
	if err != nil {
		return fmt.Errorf("rol EMPRESA_ADMIN no encontrado: %v", err)
	}

	// Asignar rol al usuario
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    userID,
		EmpresaID: empresaID,
		RoleID:    adminRole.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// Función auxiliar para determinar si un rol tiene prioridad
func isPriorityRole(roleName string) bool {
	priorityRoles := []string{"EMPRESA_ADMIN", "ADMIN_USERS", "ADMIN"}
	for _, role := range priorityRoles {
		if roleName == role {
			return true
		}
	}
	return false
}


//TODO: GetUserEmpresasWithRoles obtiene empresas del usuario con roles y permisos
func (s *authServiceImpl) GetUserEmpresasWithRoles(ctx context.Context, userID uuid.UUID) ([]EmpresaWithRole, error) {
    // Obtener todas las empresas del usuario
    empresaIDs, err := s.userEmpresaRoleRepo.FindEmpresasByUserID(ctx, userID)
    if err != nil {
        return nil, err
    }

    var empresasWithRoles []EmpresaWithRole

    for _, empresaID := range empresaIDs {
        // Obtener roles del usuario en esta empresa
        roles, err := s.GetUserRoles(ctx, userID, empresaID)
        if err != nil {
            log.Printf("Error obteniendo roles para empresa %s: %v", empresaID, err)
            continue
        }

		// ✅ NUEVO: Extraer nombres de TODOS los roles
        var roleNames []string
        for _, role := range roles {
            roleNames = append(roleNames, role.Name)
        }

        // Determinar el rol principal (el de mayor jerarquía)
        principalRole := determinePrincipalRole(roles)

        // Obtener permisos
        var allPermissions []string
        for _, role := range roles {
            permissions, err := s.GetPermissionsByRole(ctx, role.ID)
            if err != nil {
                log.Printf("Error obteniendo permisos para rol %s: %v", role.ID, err)
                continue
            }
            for _, perm := range permissions {
                allPermissions = append(allPermissions, perm.Name)
            }
        }

        // Obtener nombre de la empresa (simulación de llamada a microservicio)
        empresaName, err := s.getEmpresaName(ctx, empresaID)
        if err != nil {
            log.Printf("Error obteniendo nombre de empresa %s: %v", empresaID, err)
            empresaName = "Desconocido" // Valor por defecto
        }

        empresasWithRoles = append(empresasWithRoles, EmpresaWithRole{
            ID:          empresaID,
            Name:        empresaName,
            Roles:        roleNames,
			PrincipalRole: principalRole,
            Permissions: uniqueStrings(allPermissions),
        })
    }

    return empresasWithRoles, nil
}

//TODO: getEmpresaName simula una llamada al microservicio de empresas
//!! En producción, reemplazar con una llamada real o caché
func (s *authServiceImpl) getEmpresaName(ctx context.Context, empresaID uuid.UUID) (string, error) {
    // Simulación: en producción, usa un cliente HTTP o gRPC
    // Ejemplo: client.GetEmpresa(ctx, empresaID)
    return fmt.Sprintf("Empresa-%s", empresaID.String()), nil
}

// Función auxiliar para determinar el rol principal
func determinePrincipalRole(roles []*entities.Role) string {
	// Jerarquía de roles (de mayor a menor)
	hierarchy := []string{"EMPRESA_ADMIN", "ADMIN_USERS", "EMPLOYEE", "CLIENTE", "VIEWER"}

	for _, hierarchyRole := range hierarchy {
		for _, userRole := range roles {
			if userRole.Name == hierarchyRole {
				return hierarchyRole
			}
		}
	}

	if len(roles) > 0 {
		return roles[0].Name
	}

	return "VIEWER"
}

// Función auxiliar para obtener strings únicos
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ListUsersInEmpresa lista usuarios de una empresa específica con filtros
func (s *authServiceImpl) ListUsersInEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, filters map[string]string) ([]*UserInfo, int, error) {
	// Obtener todos los IDs de usuarios de esta empresa
	userIDs, err := s.userEmpresaRoleRepo.GetAllUsersByEmpresa(ctx, empresaID, filters["role"])
	if err != nil {
		return nil, 0, err
	}

	if len(userIDs) == 0 {
		return []*UserInfo{}, 0, nil
	}

	// Crear un nuevo mapa de filtros que incluya los IDs
	userFilters := make(map[string]interface{})
	for k, v := range filters {
		if k != "role" { // El filtro de rol ya se aplicó al obtener los userIDs
			userFilters[k] = v
		}
	}
	userFilters["ids"] = userIDs

	// Obtener usuarios con paginación y filtros
	users, total, err := s.userRepo.ListWithAdvancedFilters(ctx, page, limit, userFilters)
	if err != nil {
		return nil, 0, err
	}

	userInfos := make([]*UserInfo, len(users))

	for i, user := range users {
		// Para cada usuario, obtener sus roles en esta empresa
		roles, err := s.GetUserRoles(ctx, user.ID, empresaID)
		if err != nil {
			log.Printf("Error obteniendo roles para usuario %s: %v", user.ID, err)
			roles = []*entities.Role{}
		}

		// Convertir roles a formato simple
		roleInfos := make([]RoleSimple, len(roles))
		for j, role := range roles {
			roleInfos[j] = RoleSimple{
				ID:          role.ID,
				Name:        role.Name,
				Description: role.Description,
			}
		}

		// Crear UserInfo (sin incluir todas las empresas para esta vista)
		userInfos[i] = &UserInfo{
			ID:               user.ID,
			DNI:              user.DNI,
			Email:            user.Email,
			Nombres:          user.Nombres,
			ApellidoPaterno:  user.ApellidoPaterno,
			ApellidoMaterno:  user.ApellidoMaterno,
			NombresCompletos: user.NombresCompletos,
			Telefono:         user.Telefono,
			Status:           user.Status,
			Verified:         user.Verified,
			CreatedAt:        user.CreatedAt,
			UpdatedAt:        user.UpdatedAt,
			// Roles:            roleInfos,
		}
	}

	return userInfos, total, nil
}

// ============================================================================
// HELPER: Función para ejecutar operaciones con transacción automática
// ============================================================================

// withTransaction ejecuta una función dentro de una transacción automática
func (s *authServiceImpl) withTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
    tx, err := s.userRepo.BeginTx(ctx)
    if err != nil {
        return fmt.Errorf("error al iniciar transacción: %v", err)
    }
    
    defer func() {
        if r := recover(); r != nil {
            s.userRepo.RollbackTx(tx)
            panic(r)
        } else if err != nil {
            s.userRepo.RollbackTx(tx)
        } else {
            err = s.userRepo.CommitTx(tx)
        }
    }()
    
    err = fn(tx)
    return err
}

// ============================================================================
// EJEMPLO DE USO DEL HELPER
// ============================================================================

func (s *authServiceImpl) LoginMultiempresaWithHelper(ctx context.Context, dni, password string) (*entities.User, string, error) {
    // Buscar usuario por DNI
    user, err := s.userRepo.FindByDNI(ctx, dni)
    if err != nil {
        return nil, "", errors.New("credenciales inválidas")
    }

    // Verificar contraseña
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
        return nil, "", errors.New("credenciales inválidas")
    }

    var token string
    
    // ✅ USAR EL HELPER PARA TRANSACCIÓN AUTOMÁTICA
    err = s.withTransaction(ctx, func(tx *sql.Tx) error {
        // Invalidar sesiones antiguas
        if err := s.sessionRepo.DeleteByUserIDTx(ctx, user.ID, tx); err != nil {
            return fmt.Errorf("error al invalidar sesiones: %v", err)
        }

        // Crear claims y token
        claims := &auth.TokenClaims{
            UserID: user.ID.String(),
            DNI:    user.DNI,
            Email:  user.Email,
            RegisteredClaims: jwt.RegisteredClaims{
                ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiration)),
            },
        }

        generatedToken, err := s.jwtService.GenerateToken(claims)
        if err != nil {
            return fmt.Errorf("error al generar token: %v", err)
        }
        token = generatedToken

        // Crear sesión
        session := &entities.Session{
            ID:        uuid.New(),
            UserID:    user.ID,
            Token:     token,
            ExpiresAt: time.Now().Add(s.tokenExpiration),
            CreatedAt: time.Now(),
            UpdatedAt: time.Now(),
        }

        if err := s.sessionRepo.CreateTx(ctx, session, tx); err != nil {
            return fmt.Errorf("error al crear sesión: %v", err)
        }

        return nil
    })

    if err != nil {
        return nil, "", err
    }

    return user, token, nil
}

func (s *authServiceImpl) GetUserEmpresasWithRolesOptimized(ctx context.Context, userID uuid.UUID) ([]*entities.EmpresaConRol, error) {
    log.Printf("Obteniendo empresas optimizadas para usuario: %s", userID)
    
    // Delegar al repository optimizado
    empresas, err := s.userEmpresaRoleRepo.FindEmpresasWithRolesByUserIDOptimized(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("error obteniendo empresas optimizadas: %v", err)
    }
    
    log.Printf("Empresas optimizadas obtenidas: %d", len(empresas))
    return empresas, nil
}

