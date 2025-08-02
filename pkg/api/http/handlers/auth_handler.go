package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"auth-microservice-go.v2/pkg/application/services"
	"auth-microservice-go.v2/pkg/domain/entities"
)

// ============================================================================
// ESTRUCTURAS DE RESPUESTA Y CONFIGURACIÓN
// ============================================================================

// Response estructura estándar para respuestas HTTP exitosas
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// PaginatedResponse estructura para respuestas con paginación
type PaginatedResponse struct {
	Success    bool                   `json:"success"`
	Message    string                 `json:"message,omitempty"`
	Data       interface{}            `json:"data,omitempty"`
	Pagination map[string]interface{} `json:"pagination,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// ErrorDetail estructura para errores detallados con códigos específicos
type ErrorDetail struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Field   string                 `json:"field,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// AuthHandler maneja todas las peticiones HTTP relacionadas con autenticación
type AuthHandler struct {
	authService services.AuthService
}

// ============================================================================
// CONSTRUCTOR Y CONFIGURACIÓN DE RUTAS
// ============================================================================

// NewAuthHandler crea una nueva instancia del handler de autenticación
// Recibe el servicio de autenticación via inyección de dependencias
func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// RegisterRoutes registra todas las rutas HTTP del handler en el router
// Organiza las rutas por funcionalidad: auth básica, usuarios, empresas, etc.
func (h *AuthHandler) RegisterRoutes(router *mux.Router) {
	// ==================== RUTAS DE AUTENTICACIÓN BÁSICA ====================
	router.HandleFunc("/register", h.Register).Methods("POST")
	router.HandleFunc("/login", h.Login).Methods("POST")
	router.HandleFunc("/verify-email", h.VerifyEmail).Methods("GET", "POST")
	router.HandleFunc("/request-password-reset", h.RequestPasswordReset).Methods("POST")
	router.HandleFunc("/reset-password", h.ResetPassword).Methods("POST")
	router.HandleFunc("/change-password", h.ChangePassword).Methods("POST")

	// ==================== RUTAS DE GESTIÓN DE USUARIOS ====================
	router.HandleFunc("/me", h.GetCurrentUser).Methods("GET")
	router.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	router.HandleFunc("/users", h.ListAllUsers).Methods("GET")
	router.HandleFunc("/users/search", h.FindUserByIdentifier).Methods("GET")
	router.HandleFunc("/users/find", h.FindUserByIdentifier).Methods("GET")

	// ==================== RUTAS DE ROLES Y PERMISOS ====================
	router.HandleFunc("/users/{id}/roles", h.GetUserRoles).Methods("GET")
	router.HandleFunc("/users/{id}/permissions", h.GetUserPermissions).Methods("GET")
	router.HandleFunc("/users/me/all-permissions", h.GetCurrentUserAllPermissions).Methods("GET")
	router.HandleFunc("/users/{id}/all-permissions", h.GetAllUserPermissions).Methods("GET")

	// ==================== RUTAS MULTI-EMPRESA ====================
	router.HandleFunc("/select-empresa", h.SelectEmpresa).Methods("POST")
	router.HandleFunc("/switch-empresa", h.SelectEmpresa).Methods("POST") // Alias
	router.HandleFunc("/users/me/empresas", h.GetCurrentUserEmpresas).Methods("GET")
	router.HandleFunc("/users/{id}/empresas", h.GetUserEmpresas).Methods("GET")
	router.HandleFunc("/users/{id}/empresas/{empresaId}/add-as-client", h.AddClientToEmpresa).Methods("POST")
	router.HandleFunc("/users/empresa/{empresaId}", h.GetUsersByEmpresa).Methods("GET")
	router.HandleFunc("/empresa/{empresaId}/all-users", h.ListAllUsersInEmpresa).Methods("GET")

	// ==================== RUTAS INTERNAS (MICROSERVICIOS) ====================
	internalRouter := router.PathPrefix("/internal").Subrouter()
	internalRouter.HandleFunc("/assign-empresa-admin", h.AssignEmpresaAdminInternal).Methods("POST")
	internalRouter.HandleFunc("/get-user-empresas", h.GetUserEmpresasInternal).Methods("GET")
}

// ============================================================================
// FUNCIONES AUXILIARES PARA RESPUESTAS HTTP
// ============================================================================

// respondWithJSON envía una respuesta JSON estándar al cliente
// Establece headers apropiados y codifica la respuesta
func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// respondWithError envía una respuesta de error estándar
// Utiliza la estructura Response con success: false
func respondWithError(w http.ResponseWriter, status int, message string) {
	respondWithJSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}

// respondWithPaginatedJSON envía una respuesta JSON con información de paginación
func respondWithPaginatedJSON(w http.ResponseWriter, status int, response PaginatedResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

// respondWithPaginatedError envía un error con formato de respuesta paginada
func respondWithPaginatedError(w http.ResponseWriter, status int, message string) {
	response := PaginatedResponse{
		Success:    false,
		Error:      message,
		Data:       nil,
		Pagination: nil,
	}
	respondWithPaginatedJSON(w, status, response)
}

// respondWithValidationError envía errores de validación detallados
// Incluye códigos de error específicos y metadata adicional
func respondWithValidationError(w http.ResponseWriter, errors []ErrorDetail) {
	response := PaginatedResponse{
		Success: false,
		Error:   "Error de validación",
		Data: map[string]interface{}{
			"errors": errors,
		},
	}
	respondWithPaginatedJSON(w, http.StatusBadRequest, response)
}

// extractToken extrae el token Bearer del header Authorization
// Retorna el token sin el prefijo "Bearer " o cadena vacía si no existe
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}

// ============================================================================
// FUNCIONES DE VALIDACIÓN
// ============================================================================

// validatePaginationParams valida y convierte los parámetros de paginación
// Retorna valores por defecto si no se proporcionan y errores de validación
func validatePaginationParams(pageStr, limitStr string) (int, int, []ErrorDetail) {
	var errors []ErrorDetail
	page := 1    // Valor por defecto
	limit := 10  // Valor por defecto

	// Validar parámetro 'page'
	if pageStr != "" {
		p, err := strconv.Atoi(pageStr)
		if err != nil {
			errors = append(errors, ErrorDetail{
				Code:    "INVALID_PAGE",
				Message: "El parámetro 'page' debe ser un número",
				Field:   "page",
			})
		} else if p <= 0 {
			errors = append(errors, ErrorDetail{
				Code:    "PAGE_OUT_OF_RANGE",
				Message: "El número de página debe ser mayor a 0",
				Field:   "page",
				Meta: map[string]interface{}{
					"min": 1,
				},
			})
		} else {
			page = p
		}
	}

	// Validar parámetro 'limit'
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			errors = append(errors, ErrorDetail{
				Code:    "INVALID_LIMIT",
				Message: "El parámetro 'limit' debe ser un número",
				Field:   "limit",
			})
		} else if l <= 0 {
			errors = append(errors, ErrorDetail{
				Code:    "LIMIT_TOO_SMALL",
				Message: "El límite debe ser mayor a 0",
				Field:   "limit",
				Meta: map[string]interface{}{
					"min": 1,
				},
			})
		} else if l > 100 {
			errors = append(errors, ErrorDetail{
				Code:    "LIMIT_TOO_LARGE",
				Message: "El límite no puede ser mayor a 100",
				Field:   "limit",
				Meta: map[string]interface{}{
					"max": 100,
				},
			})
		} else {
			limit = l
		}
	}

	return page, limit, errors
}

// validateUUID valida que un string sea un UUID válido
// Retorna un ErrorDetail si la validación falla
func validateUUID(value, fieldName string) *ErrorDetail {
	if _, err := uuid.Parse(value); err != nil {
		return &ErrorDetail{
			Code:    "INVALID_UUID",
			Message: fmt.Sprintf("El %s debe ser un UUID válido", fieldName),
			Field:   fieldName,
		}
	}
	return nil
}

// min retorna el menor de dos enteros
// Función auxiliar para cálculos de paginación
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
// ============================================================================
// PARTE 2: FUNCIONES DE AUTENTICACIÓN BÁSICA
// ============================================================================

// Register maneja el registro de nuevos usuarios con información completa
// Actualizado para incluir todos los campos del usuario peruano
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición con TODOS los campos del usuario
	var req struct {
		DNI               string    `json:"dni"`
		Email             string    `json:"email"`
		Password          string    `json:"password"`
		Nombres           string    `json:"nombres"`
		ApellidoPaterno   string    `json:"apellidoPaterno"`
		ApellidoMaterno   string    `json:"apellidoMaterno"`
		NombresCompletos  string    `json:"nombresCompletos,omitempty"` // Se puede calcular automáticamente
		FechaNacimiento   time.Time `json:"fechaNacimiento,omitempty"`
		Telefono          string    `json:"telefono"`
		Departamento      string    `json:"departamento,omitempty"`
		Provincia         string    `json:"provincia,omitempty"`
		Distrito          string    `json:"distrito,omitempty"`
		DireccionCompleta string    `json:"direccionCompleta,omitempty"`
	}

	// Decodificar JSON del request body
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar campos obligatorios según el modelo peruano
	if req.DNI == "" || req.Email == "" || req.Password == "" || req.Nombres == "" || req.ApellidoPaterno == "" {
		respondWithError(w, http.StatusBadRequest, "Campos requeridos: DNI, email, password, nombres y apellido paterno")
		return
	}

	// Validar fecha de nacimiento
	if req.FechaNacimiento.IsZero() {
		respondWithError(w, http.StatusBadRequest, "Fecha de nacimiento requerida")
		return
	}

	// Generar nombres completos automáticamente si no se proporciona
	if req.NombresCompletos == "" {
		req.NombresCompletos = req.Nombres + " " + req.ApellidoPaterno
		if req.ApellidoMaterno != "" {
			req.NombresCompletos += " " + req.ApellidoMaterno
		}
	}

	// Llamar al servicio de autenticación con todos los parámetros
	user, err := h.authService.Register(
		r.Context(),
		req.DNI,
		req.Email,
		req.Password,
		req.Nombres,
		req.ApellidoPaterno,
		req.ApellidoMaterno,
		req.NombresCompletos,
		req.FechaNacimiento,
		req.Telefono,
		req.Departamento,
		req.Provincia,
		req.Distrito,
		req.DireccionCompleta,
	)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito incluyendo el usuario creado
	respondWithJSON(w, http.StatusCreated, Response{
		Success: true,
		Message: "Usuario registrado con éxito",
		Data:    user,
	})
}

// Login maneja el inicio de sesión multi-empresa
// Retorna información completa para que el cliente decida qué hacer
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Estructura simple para login (solo DNI y contraseña)
	var req struct {
		DNI      string `json:"dni"`
		Password string `json:"password"`
	}

	// Decodificar request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar campos requeridos
	if req.DNI == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "DNI y contraseña son requeridos")
		return
	}

	// Autenticar usuario usando LoginMultiempresa
	user, token, err := h.authService.LoginMultiempresa(r.Context(), req.DNI, req.Password)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener empresas del usuario con roles y permisos
	empresas, err := h.authService.GetUserEmpresasWithRoles(r.Context(), user.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error obteniendo empresas")
		return
	}

	// Verificar si es SUPER_ADMIN del sistema
	isSuperAdmin, _ := h.authService.HasSystemRole(r.Context(), user.ID, "SUPER_ADMIN")

	// Respuesta completa para que Flutter pueda decidir qué mostrar
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"token":                 token,        // Token básico (sin empresa específica)
			"user":                  user,         // Información completa del usuario
			"empresas":              empresas,     // Lista de empresas con roles
			"isSuperAdmin":          isSuperAdmin, // Flag para permisos especiales
			"needsEmpresaSelection": len(empresas) > 1, // Si tiene múltiples empresas
		},
	})
}

// // SelectEmpresa maneja la selección de empresa específica después del login
// // Genera un nuevo token con contexto de empresa
// func (h *AuthHandler) SelectEmpresa(w http.ResponseWriter, r *http.Request) {
// 	// Extraer token básico del header
// 	token := extractToken(r)
// 	if token == "" {
// 		respondWithError(w, http.StatusUnauthorized, "No autorizado")
// 		return
// 	}

// 	// Verificar token básico
// 	claims, err := h.authService.VerifyToken(r.Context(), token)
// 	if err != nil {
// 		respondWithError(w, http.StatusUnauthorized, err.Error())
// 		return
// 	}

// 	// Estructura para la empresa seleccionada
// 	var req struct {
// 		EmpresaID uuid.UUID `json:"empresaId"`
// 	}

// 	// Decodificar request
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Petición inválida")
// 		return
// 	}

// 	userID := uuid.MustParse(claims.UserID)

// 	// Verificar que el usuario pertenece a esa empresa
// 	hasAccess, err := h.authService.UserBelongsToEmpresa(r.Context(), userID, req.EmpresaID)
// 	if err != nil || !hasAccess {
// 		respondWithError(w, http.StatusForbidden, "No tienes acceso a esta empresa")
// 		return
// 	}

// 	// Generar nuevo token con empresa seleccionada
// 	newToken, err := h.authService.GenerateTokenWithEmpresa(r.Context(), userID, req.EmpresaID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generando token")
// 		return
// 	}

// 	// Obtener roles y permisos específicos para la empresa seleccionada
// 	roles, err := h.authService.GetUserRoles(r.Context(), userID, req.EmpresaID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error obteniendo roles")
// 		return
// 	}

// 	// Responder con nuevo token y contexto de empresa
// 	respondWithJSON(w, http.StatusOK, Response{
// 		Success: true,
// 		Data: map[string]interface{}{
// 			"token":     newToken,       // Nuevo token con empresa específica
// 			"empresaId": req.EmpresaID,  // ID de empresa seleccionada
// 			"roles":     roles,          // Roles del usuario en esa empresa
// 		},
// 	})
// }

func (h *AuthHandler) SelectEmpresa(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close() // Cerrar el body de la solicitud

    // Extraer token básico del header
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token básico
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    // Verificar que el token no tenga EmpresaID
    if claims.EmpresaID != "" {
        respondWithError(w, http.StatusBadRequest, "El token ya está asociado a una empresa")
        return
    }

    // Estructura para la empresa seleccionada
    var req struct {
        EmpresaID uuid.UUID `json:"empresaId"`
    }

    // Decodificar request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Petición inválida")
        return
    }

    userID := uuid.MustParse(claims.UserID)

    // Verificar que el usuario pertenece a esa empresa
    hasAccess, err := h.authService.UserBelongsToEmpresa(r.Context(), userID, req.EmpresaID)
    if err != nil || !hasAccess {
        respondWithError(w, http.StatusForbidden, "No tienes acceso a esta empresa")
        return
    }

    // Generar nuevo token con empresa seleccionada
    newToken, err := h.authService.GenerateTokenWithEmpresa(r.Context(), userID, req.EmpresaID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Error generando token")
        return
    }

    // Obtener roles y permisos específicos para la empresa seleccionada
    roles, err := h.authService.GetUserRoles(r.Context(), userID, req.EmpresaID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Error obteniendo roles")
        return
    }

    // Responder con nuevo token y contexto de empresa
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data: map[string]interface{}{
            "token":     newToken,       // Nuevo token con empresa específica
            "empresaId": req.EmpresaID,  // ID de empresa seleccionada
            "roles":     roles,          // Roles del usuario en esa empresa
        },
    })
}


// VerifyEmail verifica el email de un usuario usando un token
// Maneja tanto GET (desde email) como POST (desde aplicación)
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var token string

	// Obtener token dependiendo del método HTTP
	if r.Method == "GET" {
		// Desde enlace en email
		token = r.URL.Query().Get("token")
	} else {
		// Desde aplicación (POST)
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, "Petición inválida")
			return
		}
		token = req.Token
	}

	// Validar que el token existe
	if token == "" {
		respondWithError(w, http.StatusBadRequest, "Token requerido")
		return
	}

	// Verificar email usando el servicio
	err := h.authService.VerifyEmail(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder según el método usado
	if r.Method == "GET" {
		// Redirigir a página de éxito (para enlaces de email)
		http.Redirect(w, r, "/email-verified.html", http.StatusSeeOther)
		return
	}

	// Responder JSON (para aplicaciones)
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Email verificado con éxito",
	})
}

// RequestPasswordReset solicita un reseteo de contraseña
// Envía un email con token de reseteo al usuario
// func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
// 	// Estructura simple para email
// 	var req struct {
// 		Email string `json:"email"`
// 	}

// 	// Decodificar request
// 	err := json.NewDecoder(r.Body).Decode(&req)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Petición inválida")
// 		return
// 	}

// 	// Validar email requerido
// 	if req.Email == "" {
// 		respondWithError(w, http.StatusBadRequest, "Email requerido")
// 		return
// 	}

// 	// Solicitar reseteo a través del servicio
// 	token, err := h.authService.RequestPasswordReset(r.Context(), req.Email)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	// Responder con éxito (incluir token solo para desarrollo/testing)
// 	respondWithJSON(w, http.StatusOK, Response{
// 		Success: true,
// 		Message: "Solicitud de reseteo de contraseña enviada",
// 		Data: map[string]string{
// 			"token": token.Token, // Solo para testing - remover en producción
// 		},
// 	})
// }

// RequestPasswordReset solicita un reseteo de contraseña
// Envía un email con token de reseteo al usuario
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close() // Cerrar el body de la solicitud

    // Estructura simple para email
    var req struct {
        Email string `json:"email"`
    }

    // Decodificar request
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "Petición inválida")
        return
    }

    // Validar email requerido
    if req.Email == "" {
        respondWithError(w, http.StatusBadRequest, "Email requerido")
        return
    }

    // Solicitar reseteo a través del servicio
    _, err = h.authService.RequestPasswordReset(r.Context(), req.Email)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, err.Error())
        return
    }

    // Responder con éxito (sin incluir token en producción)
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Message: "Solicitud de reseteo de contraseña enviada",
        Data:    nil,
    })
}

// ResetPassword resetea la contraseña usando un token de verificación
// Utiliza el token enviado por email
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Estructura para token y nueva contraseña
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	// Decodificar request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar campos requeridos
	if req.Token == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Token y nueva contraseña requeridos")
		return
	}

	// Resetear contraseña a través del servicio
	err = h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Contraseña restablecida con éxito",
	})
}

// ChangePassword cambia la contraseña de un usuario autenticado
// Requiere contraseña actual para validación de seguridad
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Obtener y verificar token de autorización
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Estructura para cambio de contraseña
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	// Decodificar request
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar campos requeridos
	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Contraseña actual y nueva requeridas")
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Cambiar contraseña verificando la actual
	err = h.authService.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Contraseña cambiada con éxito",
	})
}

// ============================================================================
// PARTE 3: GESTIÓN DE USUARIOS Y PERMISOS
// ============================================================================

// GetCurrentUser obtiene la información del usuario autenticado
// Extrae el ID del usuario del token JWT
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Obtener y verificar token
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y extraer claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Obtener información completa del usuario
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// Responder con información del usuario
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    user,
	})
}

// GetUser obtiene un usuario específico por su ID
// Requiere autenticación pero no validación especial de permisos
func (h *AuthHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener usuario por ID
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// Responder con información del usuario
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    user,
	})
}

// FindUserByIdentifier busca un usuario por DNI, email o teléfono
// Usado para encontrar usuarios antes de agregarlos a empresas
func (h *AuthHandler) FindUserByIdentifier(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener información del usuario que busca
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener identificador de los query params
	identifier := r.URL.Query().Get("identifier")
	if identifier == "" {
		respondWithError(w, http.StatusBadRequest, "Identificador requerido (DNI, email o teléfono)")
		return
	}

	// Log para auditoría (quién busca qué)
	log.Printf("Usuario %s está buscando por identificador: %s", claims.UserID, identifier)

	// Buscar usuario usando el servicio
	user, err := h.authService.FindUserByIdentifier(r.Context(), identifier)
	if err != nil {
		// No mostrar error específico por seguridad
		respondWithJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    nil,
			Message: "Usuario no encontrado",
		})
		return
	}

	// Preparar datos mínimos para respuesta (sin información sensible)
	userData := map[string]interface{}{
		"id":                user.ID,
		"dni":               user.DNI,
		"nombres":           user.Nombres,
		"apellidoMaterno":   user.ApellidoMaterno,
		"nombresCompletos":  user.NombresCompletos,
		"email":             user.Email,
		"telefono":          user.Telefono,
		// No incluir información sobre empresas por seguridad
	}

	// Responder con información básica del usuario encontrado
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    userData,
	})
}

// // ListAllUsers lista todos los usuarios del sistema (solo SUPER_ADMIN)
// // Incluye paginación y filtros por estado y búsqueda
// func (h *AuthHandler) ListAllUsers(w http.ResponseWriter, r *http.Request) {
// 	// Verificar autenticación básica
// 	token := extractToken(r)
// 	if token == "" {
// 		respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
// 		return
// 	}

// 	// Verificar token y obtener claims
// 	claims, err := h.authService.VerifyToken(r.Context(), token)
// 	if err != nil {
// 		respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
// 		return
// 	}

// 	// Obtener ID del usuario del token
// 	currentUserID, err := uuid.Parse(claims.UserID)
// 	if err != nil {
// 		respondWithPaginatedError(w, http.StatusInternalServerError, "Error en el token")
// 		return
// 	}

// 	// VERIFICACIÓN CRÍTICA: Solo SUPER_ADMIN puede listar todos los usuarios
// 	isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
// 	if err != nil {
// 		log.Printf("Error verificando rol SUPER_ADMIN: %v", err)
// 		respondWithPaginatedError(w, http.StatusInternalServerError, "Error verificando permisos")
// 		return
// 	}

// 	if !isSuperAdmin {
// 		respondWithPaginatedError(w, http.StatusForbidden, "Acceso denegado. Se requiere rol SUPER_ADMIN")
// 		return
// 	}

// 	// Validar parámetros de paginación
// 	pageStr := r.URL.Query().Get("page")
// 	limitStr := r.URL.Query().Get("limit")
// 	page, limit, validationErrors := validatePaginationParams(pageStr, limitStr)

// 	if len(validationErrors) > 0 {
// 		respondWithValidationError(w, validationErrors)
// 		return
// 	}

// 	// Preparar filtros adicionales
// 	filters := make(map[string]string)

// 	// Filtro por estado (ACTIVE, INACTIVE, BLOCKED)
// 	if status := r.URL.Query().Get("status"); status != "" {
// 		validStatuses := []string{
// 			string(entities.UserStatusActive),
// 			string(entities.UserStatusInactive),
// 			string(entities.UserStatusBlocked),
// 		}
// 		isValid := false
// 		for _, validStatus := range validStatuses {
// 			if status == validStatus {
// 				isValid = true
// 				break
// 			}
// 		}

// 		if !isValid {
// 			errors := []ErrorDetail{{
// 				Code:    "INVALID_STATUS",
// 				Message: "El estado especificado no es válido",
// 				Field:   "status",
// 				Meta: map[string]interface{}{
// 					"validStatuses": validStatuses,
// 				},
// 			}}
// 			respondWithValidationError(w, errors)
// 			return
// 		}

// 		filters["status"] = status
// 	}

// 	// Filtro por texto de búsqueda (nombre, apellido, email, DNI)
// 	if searchTerm := r.URL.Query().Get("search"); searchTerm != "" {
// 		filters["search"] = searchTerm
// 	}

// 	// Obtener usuarios con paginación y filtros
// 	users, total, err := h.authService.ListAllUsers(r.Context(), page, limit, filters)
// 	if err != nil {
// 		log.Printf("Error obteniendo usuarios: %v", err)
// 		respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
// 		return
// 	}

// 	// Calcular información de paginación
// 	totalPages := (total + limit - 1) / limit

// 	// Responder con usuarios y metadata de paginación
// 	response := PaginatedResponse{
// 		Success: true,
// 		Message: "Usuarios obtenidos exitosamente",
// 		Data:    users,
// 		Pagination: map[string]interface{}{
// 			"page":       page,
// 			"limit":      limit,
// 			"total":      total,
// 			"totalPages": totalPages,
// 			"hasNext":    page < totalPages,
// 			"hasPrev":    page > 1,
// 			"from":       (page-1)*limit + 1,
// 			"to":         min(page*limit, total),
// 		},
// 	}

// 	respondWithPaginatedJSON(w, http.StatusOK, response)
// }

// ListAllUsers lista todos los usuarios del sistema (solo SUPER_ADMIN)
// Incluye paginación y filtros por estado y búsqueda
func (h *AuthHandler) ListAllUsers(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close() // Cerrar el body de la solicitud

    // Verificar autenticación básica
    token := extractToken(r)
    if token == "" {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
        return
    }

    // Verificar token y obtener claims
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
        return
    }

    // Obtener ID del usuario del token
    currentUserID, err := uuid.Parse(claims.UserID)
    if err != nil {
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

    // VERIFICACIÓN CRÍTICA: Solo SUPER_ADMIN puede listar todos los usuarios
    isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
    if err != nil {
        log.Printf("Error verificando rol SUPER_ADMIN: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error verificando permisos")
        return
    }

    if !isSuperAdmin {
        respondWithPaginatedError(w, http.StatusForbidden, "Acceso denegado. Se requiere rol SUPER_ADMIN")
        return
    }

    // Validar parámetros de paginación
    pageStr := r.URL.Query().Get("page")
    limitStr := r.URL.Query().Get("limit")
    page, limit, validationErrors := validatePaginationParams(pageStr, limitStr)

    if len(validationErrors) > 0 {
        respondWithValidationError(w, validationErrors)
        return
    }

    // Preparar filtros adicionales
    filters := make(map[string]string)

    // Filtro por estado (ACTIVE, INACTIVE, BLOCKED)
    if status := r.URL.Query().Get("status"); status != "" {
        validStatuses := []entities.UserStatus{
            entities.UserStatusActive,
            entities.UserStatusInactive,
            entities.UserStatusBlocked,
        }
        isValid := false
        for _, validStatus := range validStatuses {
            if status == string(validStatus) {
                isValid = true
                break
            }
        }

        if !isValid {
            errors := []ErrorDetail{{
                Code:    "INVALID_STATUS",
                Message: "El estado especificado no es válido",
                Field:   "status",
                Meta: map[string]interface{}{
                    "validStatuses": []string{
                        string(entities.UserStatusActive),
                        string(entities.UserStatusInactive),
                        string(entities.UserStatusBlocked),
                    },
                },
            }}
            respondWithValidationError(w, errors)
            return
        }

        filters["status"] = status
    }

    // Filtro por texto de búsqueda (nombre, apellido, email, DNI)
    if searchTerm := r.URL.Query().Get("search"); searchTerm != "" {
        filters["search"] = searchTerm
    }

    // Obtener usuarios con paginación y filtros
    users, total, err := h.authService.ListAllUsers(r.Context(), page, limit, filters)
    if err != nil {
        log.Printf("Error obteniendo usuarios: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
        return
    }

    // Calcular información de paginación
    totalPages := (total + limit - 1) / limit

    // Responder con usuarios y metadata de paginación
    response := PaginatedResponse{
        Success: true,
        Message: "Usuarios obtenidos exitosamente",
        Data:    users,
        Pagination: map[string]interface{}{
            "page":       page,
            "limit":      limit,
            "total":      total,
            "totalPages": totalPages,
            "hasNext":    page < totalPages,
            "hasPrev":    page > 1,
            "from":       (page-1)*limit + 1,
            "to":         min(page*limit, total),
        },
    }

    respondWithPaginatedJSON(w, http.StatusOK, response)
}

// ============================================================================
// PARTE 4: GESTIÓN DE ROLES Y PERMISOS
// ============================================================================

// GetUserRoles obtiene los roles de un usuario en una empresa específica
// Requiere ID de usuario y empresa como parámetros
func (h *AuthHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener ID de la empresa de los query params
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener roles del usuario en esa empresa
	roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con los roles encontrados
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    roles,
	})
}

// GetUserPermissions obtiene permisos específicos de un usuario en una empresa
// Permite verificar múltiples permisos a la vez
func (h *AuthHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener ID de la empresa de los query params
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener lista de permisos a verificar desde query params
	perms := r.URL.Query()["permission"]

	// Mapa para almacenar resultados de verificación
	permResults := make(map[string]bool)

	// Verificar cada permiso individualmente
	for _, perm := range perms {
		hasPermission, err := h.authService.HasPermission(r.Context(), userID, empresaID, perm)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		permResults[perm] = hasPermission
	}

	// Responder con mapa de permisos verificados
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    permResults,
	})
}

// GetAllUserPermissions obtiene TODOS los permisos de un usuario en una empresa
// Solo usuarios autorizados pueden ver permisos de otros
func (h *AuthHandler) GetAllUserPermissions(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario objetivo de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// VERIFICACIÓN DE AUTORIZACIÓN: Solo el mismo usuario o SUPER_ADMIN
	if claims.UserID != userID.String() {
		currentUserID := uuid.MustParse(claims.UserID)

		// Verificar si es SUPER_ADMIN del sistema
		isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
		if err != nil {
			log.Printf("Error verificando rol de sistema: %v", err)
			respondWithError(w, http.StatusInternalServerError, "Error verificando permisos")
			return
		}

		if !isSuperAdmin {
			respondWithError(w, http.StatusForbidden, "No autorizado para ver permisos de otro usuario")
			return
		}
	}

	// Obtener ID de empresa requerido
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener todos los roles del usuario en la empresa
	roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Estructura para respuesta de permisos completos
	type UserPermissionsResponse struct {
		Roles       []string        `json:"roles"`
		Permissions map[string]bool `json:"permissions"`
	}

	response := UserPermissionsResponse{
		Roles:       make([]string, 0),
		Permissions: make(map[string]bool),
	}

	// Procesar cada rol para obtener sus permisos
	for _, role := range roles {
		response.Roles = append(response.Roles, role.Name)

		// Obtener permisos específicos del rol
		permissions, err := h.authService.GetPermissionsByRole(r.Context(), role.ID)
		if err != nil {
			log.Printf("Error obteniendo permisos del rol %s: %v", role.Name, err)
			continue
		}

		// Agregar cada permiso al mapa
		for _, permission := range permissions {
			response.Permissions[permission.Name] = true
		}
	}

	// Responder con información completa de permisos
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    response,
	})
}

// GetCurrentUserAllPermissions obtiene todos los permisos del usuario autenticado
// Versión simplificada para el usuario actual
func (h *AuthHandler) GetCurrentUserAllPermissions(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Obtener ID de empresa requerido
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener roles del usuario en la empresa
	roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Estructura para respuesta
	type UserPermissionsResponse struct {
		Roles       []string        `json:"roles"`
		Permissions map[string]bool `json:"permissions"`
	}

	response := UserPermissionsResponse{
		Roles:       make([]string, 0),
		Permissions: make(map[string]bool),
	}

	// Procesar roles y permisos
	for _, role := range roles {
		response.Roles = append(response.Roles, role.Name)

		// Obtener permisos del rol
		permissions, err := h.authService.GetPermissionsByRole(r.Context(), role.ID)
		if err != nil {
			log.Printf("Error obteniendo permisos del rol %s: %v", role.Name, err)
			continue
		}

		// Agregar permisos al mapa
		for _, permission := range permissions {
			response.Permissions[permission.Name] = true
		}
	}

	// Responder con permisos del usuario actual
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    response,
	})
}

// ============================================================================
// PARTE 5: GESTIÓN MULTI-EMPRESA
// ============================================================================

// GetCurrentUserEmpresas obtiene todas las empresas del usuario autenticado
// Retorna solo IDs de empresas, no información detallada
func (h *AuthHandler) GetCurrentUserEmpresas(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Obtener empresas asociadas al usuario
	empresasIDs, err := h.authService.GetUserEmpresas(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con lista de IDs de empresas
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    empresasIDs,
	})
}

// GetUserEmpresas obtiene empresas de un usuario específico
// Requiere permisos especiales para ver empresas de otros usuarios
func (h *AuthHandler) GetUserEmpresas(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario objetivo de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// VERIFICACIÓN DE PERMISOS: Si no es el mismo usuario, verificar autorización
	requestedUserIDStr := userID.String()
	currentUserID := uuid.MustParse(claims.UserID)

	if claims.UserID != requestedUserIDStr {
		// Verificar múltiples tipos de permisos que podrían aplicar
		
		// 1. SUPER_ADMIN - Puede ver empresas de cualquier usuario
		hasSuperAdminPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "SUPER_ADMIN")
		
		// 2. EMPRESA_ADMIN - Puede administrar usuarios
		hasAdminUsersPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "EMPRESA_ADMIN")
		
		// 3. VIEW_PARTNER_EMPRESAS - Permiso específico para tercerización
		hasViewPartnerPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "VIEW_PARTNER_EMPRESAS")
		
		// Denegar acceso si no tiene ninguno de estos permisos
		if !hasSuperAdminPermission && !hasAdminUsersPermission && !hasViewPartnerPermission {
			respondWithError(w, http.StatusForbidden, "No tienes permiso para ver las empresas de este usuario")
			return
		}
	}

	// Obtener empresas del usuario objetivo
	empresasIDs, err := h.authService.GetUserEmpresas(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con empresas encontradas
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    empresasIDs,
	})
}

// AddClientToEmpresa añade un usuario como cliente a una empresa específica
// Requiere permisos administrativos en la empresa
func (h *AuthHandler) AddClientToEmpresa(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	log.Printf("Token verificado correctamente para usuario: %s", claims.UserID)

	// Obtener IDs de usuario y empresa de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		log.Printf("Error parseando ID de usuario: %v", err)
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}
	empresaID, err := uuid.Parse(vars["empresaId"])
	if err != nil {
		log.Printf("Error parseando ID de empresa: %v", err)
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener ID del usuario que realiza la operación
	currentUserID, err := uuid.Parse(claims.UserID)
	if err != nil {
		log.Printf("Error parseando ID de usuario del token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	log.Printf("Verificando permisos para usuario %s en empresa %s", currentUserID, empresaID)

	// VERIFICACIÓN DE PERMISOS: Debe ser admin de la empresa
	hasPermission := false
	
	// Verificar si es administrador de la empresa
	isEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
	if err != nil {
		log.Printf("Error verificando permiso EMPRESA_ADMIN: %v", err)
	} else if isEmpresaAdmin {
		hasPermission = true
		log.Printf("Usuario tiene permiso EMPRESA_ADMIN")
	}

	// Si no es admin de empresa, verificar permiso específico para administrar usuarios
	if !hasPermission {
		isAdminUsers, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "ADMIN_USERS")
		if err != nil {
			log.Printf("Error verificando permiso ADMIN_USERS: %v", err)
		} else if isAdminUsers {
			hasPermission = true
			log.Printf("Usuario tiene permiso ADMIN_USERS")
		}
	}

	if !hasPermission {
		log.Printf("Usuario no tiene permisos para añadir clientes a esta empresa")
		respondWithError(w, http.StatusForbidden, "No tienes permiso para añadir clientes a esta empresa")
		return
	}

	// Realizar operación de agregar cliente
	log.Printf("Añadiendo cliente %s a empresa %s", userID, empresaID)
	if err := h.authService.AddClientToEmpresa(r.Context(), userID, empresaID); err != nil {
		log.Printf("Error añadiendo cliente: %v", err)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con éxito
	log.Printf("Cliente añadido exitosamente")
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Usuario añadido como cliente a la empresa",
	})
}

// GetUsersByEmpresa obtiene usuarios de una empresa con paginación y filtros
// Incluye validación exhaustiva de permisos y parámetros
func (h *AuthHandler) GetUsersByEmpresa(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
		return
	}

	// Obtener y validar ID de la empresa de la URL
	vars := mux.Vars(r)
	empresaIDStr := vars["empresaId"]

	if errDetail := validateUUID(empresaIDStr, "empresaId"); errDetail != nil {
		respondWithValidationError(w, []ErrorDetail{*errDetail})
		return
	}

	empresaID := uuid.MustParse(empresaIDStr)

	// Validar parámetros de paginación
	page, limit, validationErrors := validatePaginationParams(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
	)

	if len(validationErrors) > 0 {
		respondWithValidationError(w, validationErrors)
		return
	}

	// Obtener y validar filtro de rol
	roleFilter := r.URL.Query().Get("role")
	if roleFilter != "" {
		// Lista de roles válidos permitidos
		validRoles := []string{"EMPRESA_ADMIN", "SUPER_ADMIN", "CLIENTE", "EMPLOYEE", "VIEWER"}
		isValidRole := false
		for _, validRole := range validRoles {
			if roleFilter == validRole {
				isValidRole = true
				break
			}
		}

		if !isValidRole {
			errors := []ErrorDetail{{
				Code:    "INVALID_ROLE",
				Message: "El rol especificado no es válido",
				Field:   "role",
				Meta: map[string]interface{}{
					"validRoles": validRoles,
				},
			}}
			respondWithValidationError(w, errors)
			return
		}
	}

	// VERIFICACIÓN DE PERMISOS: Jerarquía de autorización
	currentUserID := uuid.MustParse(claims.UserID)

	// Primer nivel: Verificar si es SUPER_ADMIN del sistema
	isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
	if err != nil {
		log.Printf("Error verificando rol de sistema: %v", err)
		respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos del sistema")
		return
	}

	if isSuperAdmin {
		log.Printf("Usuario %s es SUPER_ADMIN del sistema", currentUserID)
		// SUPER_ADMIN puede ver todo, continuar con la operación
	} else {
		// Segundo nivel: Verificar permisos específicos en la empresa
		hasPermission, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "ADMIN_USERS")
		if err != nil {
			respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos")
			return
		}

		if !hasPermission {
			// Tercer nivel: Verificar si es EMPRESA_ADMIN
			hasEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
			if err != nil {
				respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos de empresa")
				return
			}

			if !hasEmpresaAdmin {
				respondWithPaginatedError(w, http.StatusForbidden, "No tienes permisos para ver usuarios de esta empresa")
				return
			}
		}
	}

	// Obtener usuarios de la empresa con paginación y filtros
	users, total, err := h.authService.GetUsersByEmpresa(r.Context(), empresaID, page, limit, roleFilter)
	if err != nil {
		// Manejo específico de errores del servicio
		switch err.Error() {
		case "empresa no encontrada":
			respondWithPaginatedError(w, http.StatusNotFound, "Empresa no encontrada")
		case "rol no válido":
			errors := []ErrorDetail{{
				Code:    "INVALID_ROLE",
				Message: "Rol de filtro no válido",
				Field:   "role",
			}}
			respondWithValidationError(w, errors)
		case "sin permisos":
			respondWithPaginatedError(w, http.StatusForbidden, "Sin permisos para acceder a esta información")
		default:
			log.Printf("Error obteniendo usuarios de empresa: %v", err)
			respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
		}
		return
	}

	// Calcular información de paginación
	totalPages := (total + limit - 1) / limit

	// Responder con usuarios y metadata completa
	response := PaginatedResponse{
		Success: true,
		Message: "Usuarios obtenidos exitosamente",
		Data:    users,
		Pagination: map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": totalPages,
			"hasNext":    page < totalPages,
			"hasPrev":    page > 1,
			"from":       (page-1)*limit + 1,
			"to":         min(page*limit, total),
		},
	}

	respondWithPaginatedJSON(w, http.StatusOK, response)
}

// ListAllUsersInEmpresa lista todos los usuarios de una empresa específica
// Similar a GetUsersByEmpresa pero con diferentes restricciones de permisos
func (h *AuthHandler) ListAllUsersInEmpresa(w http.ResponseWriter, r *http.Request) {
	// Verificar autenticación
	token := extractToken(r)
	if token == "" {
		respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
		return
	}

	// Verificar token y obtener claims
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
		return
	}

	// Obtener ID del usuario del token
	currentUserID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithPaginatedError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Obtener y validar ID de la empresa
	vars := mux.Vars(r)
	empresaIDStr := vars["empresaId"]

	if errDetail := validateUUID(empresaIDStr, "empresaId"); errDetail != nil {
		respondWithValidationError(w, []ErrorDetail{*errDetail})
		return
	}

	empresaID := uuid.MustParse(empresaIDStr)

	// VERIFICACIÓN DE PERMISOS: SUPER_ADMIN o permisos específicos en empresa
	isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
	if err != nil {
		log.Printf("Error verificando rol SUPER_ADMIN: %v", err)
		respondWithPaginatedError(w, http.StatusInternalServerError, "Error verificando permisos")
		return
	}

	// Si no es SUPER_ADMIN, verificar permisos específicos en la empresa
	if !isSuperAdmin {
		// Verificar si es administrador de la empresa
		isEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
		if err != nil || !isEmpresaAdmin {
			// Verificar si tiene permiso para ver usuarios
			hasViewPermission, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "VIEW_USERS")
			if err != nil || !hasViewPermission {
				respondWithPaginatedError(w, http.StatusForbidden, "No tienes permisos para ver usuarios de esta empresa")
				return
			}
		}
	}

	// Validar parámetros de paginación
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	page, limit, validationErrors := validatePaginationParams(pageStr, limitStr)

	if len(validationErrors) > 0 {
		respondWithValidationError(w, validationErrors)
		return
	}

	// Preparar filtros adicionales
	filters := make(map[string]string)

	// Filtro por rol específico
	if role := r.URL.Query().Get("role"); role != "" {
		filters["role"] = role
	}

	// Filtro por estado de usuario
	if status := r.URL.Query().Get("status"); status != "" {
		validStatuses := []string{"ACTIVE", "INACTIVE", "BLOCKED"}
		isValid := false
		for _, validStatus := range validStatuses {
			if status == validStatus {
				isValid = true
				break
			}
		}

		if !isValid {
			errors := []ErrorDetail{{
				Code:    "INVALID_STATUS",
				Message: "El estado especificado no es válido",
				Field:   "status",
				Meta: map[string]interface{}{
					"validStatuses": validStatuses,
				},
			}}
			respondWithValidationError(w, errors)
			return
		}

		filters["status"] = status
	}

	// Filtro por texto de búsqueda (nombre, apellido, email, DNI)
	if searchTerm := r.URL.Query().Get("search"); searchTerm != "" {
		filters["search"] = searchTerm
	}

	// Obtener usuarios de la empresa con filtros aplicados
	users, total, err := h.authService.ListUsersInEmpresa(r.Context(), empresaID, page, limit, filters)
	if err != nil {
		log.Printf("Error obteniendo usuarios: %v", err)
		respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
		return
	}

	// Calcular información de paginación
	totalPages := (total + limit - 1) / limit

	// Responder con usuarios de la empresa
	response := PaginatedResponse{
		Success: true,
		Message: "Usuarios obtenidos exitosamente",
		Data:    users,
		Pagination: map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": totalPages,
			"hasNext":    page < totalPages,
			"hasPrev":    page > 1,
			"from":       (page-1)*limit + 1,
			"to":         min(page*limit, total),
		},
	}

	respondWithPaginatedJSON(w, http.StatusOK, response)
}

// ============================================================================
// PARTE 6: RUTAS INTERNAS PARA COMUNICACIÓN ENTRE MICROSERVICIOS
// ============================================================================

// AssignEmpresaAdminInternal asigna rol de administrador de empresa (ruta interna)
// Esta función es llamada por otros microservicios cuando se crea una empresa
func (h *AuthHandler) AssignEmpresaAdminInternal(w http.ResponseWriter, r *http.Request) {
	// NOTA: En producción aquí debería ir autenticación de servicio a servicio
	// Por ejemplo: API Key, mutual TLS, etc.

	// Estructura para la petición interna
	var req struct {
		UserID    uuid.UUID `json:"userId"`
		EmpresaID uuid.UUID `json:"empresaId"`
	}

	// Decodificar request JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar que se proporcionaron ambos IDs
	if req.UserID == uuid.Nil || req.EmpresaID == uuid.Nil {
		respondWithError(w, http.StatusBadRequest, "UserID y EmpresaID son requeridos")
		return
	}

	// Asignar rol de administrador usando el servicio
	if err := h.authService.AssignEmpresaAdmin(r.Context(), req.UserID, req.EmpresaID); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Administrador de empresa asignado correctamente",
	})
}

// GetUserEmpresasInternal obtiene empresas de un usuario (ruta interna)
// Usado por otros microservicios para obtener contexto de usuario
func (h *AuthHandler) GetUserEmpresasInternal(w http.ResponseWriter, r *http.Request) {
	// NOTA: En producción aquí debería ir autenticación de servicio a servicio

	// Obtener userID de los query parameters
	userIDStr := r.URL.Query().Get("userId")
	if userIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "userId requerido")
		return
	}

	// Validar formato UUID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "userId inválido")
		return
	}

	// Obtener empresas del usuario con información de roles
	empresas, err := h.authService.GetUserEmpresasWithRoles(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con información completa de empresas y roles
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    empresas,
	})
}