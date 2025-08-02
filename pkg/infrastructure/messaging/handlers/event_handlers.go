// pkg/infrastructure/messaging/handlers/event_handlers.go
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-microservice-go.v2/pkg/application/services"
	"auth-microservice-go.v2/pkg/domain/entities"
	"auth-microservice-go.v2/pkg/infrastructure/messaging/rabbitmq"
)

// ============================================================================
// ESTRUCTURAS DE EVENTOS
// ============================================================================

// EmpresaCreatedEvent representa un evento de creación de empresa
// Este evento llega cuando el microservicio de empresas crea una nueva empresa
type EmpresaCreatedEvent struct {
	ID                string    `json:"id"`
	RazonSocial       string    `json:"razonSocial"`
	NombreComercial   string    `json:"nombreComercial"`
	RUC               string    `json:"ruc"`
	CreadorID         string    `json:"creadorId"`
	CreadorDNI        string    `json:"creadorDni"`
	CreadorEmail      string    `json:"creadorEmail"`
	CreadorNombres    string    `json:"creadorNombres"`
	CreadorApellidos  string    `json:"creadorApellidos"`
	CreadorTelefono   string    `json:"creadorTelefono"`
	CreatedAt         time.Time `json:"createdAt"`
}

// UsuarioCreatedEvent representa un evento de creación de usuario en una empresa
// Este evento llega cuando se agrega un empleado a una empresa
type UsuarioCreatedEvent struct {
	ID              string    `json:"id"`
	DNI             string    `json:"dni"`
	Email           string    `json:"email"`
	Nombres         string    `json:"nombres"`
	ApellidoPaterno string    `json:"apellidoPaterno"`
	ApellidoMaterno string    `json:"apellidoMaterno"`
	Telefono        string    `json:"telefono"`
	EmpresaID       string    `json:"empresaId"`
	RolID           string    `json:"rolId"`
	RolName         string    `json:"rolName"`
	CreatedAt       time.Time `json:"createdAt"`
}

// ClienteCreatedEvent representa un evento de creación de cliente en una empresa
// Este evento llega cuando se registra un cliente para una empresa
type ClienteCreatedEvent struct {
	ID              string    `json:"id"`
	DNI             string    `json:"dni"`
	Email           string    `json:"email"`
	Nombres         string    `json:"nombres"`
	ApellidoPaterno string    `json:"apellidoPaterno"`
	ApellidoMaterno string    `json:"apellidoMaterno"`
	Telefono        string    `json:"telefono"`
	EmpresaID       string    `json:"empresaId"`
	CreatedAt       time.Time `json:"createdAt"`
}

// UserRoleUpdatedEvent representa un cambio de rol de usuario
type UserRoleUpdatedEvent struct {
	UserID    string `json:"userId"`
	EmpresaID string `json:"empresaId"`
	OldRoleID string `json:"oldRoleId"`
	NewRoleID string `json:"newRoleId"`
	UpdatedBy string `json:"updatedBy"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ============================================================================
// EVENT HANDLER PRINCIPAL
// ============================================================================

// EventHandler maneja todos los eventos recibidos de RabbitMQ
type EventHandler struct {
	authService services.AuthService
}

// NewEventHandler crea una nueva instancia del manejador de eventos
func NewEventHandler(authService services.AuthService) *EventHandler {
	return &EventHandler{
		authService: authService,
	}
}

// ============================================================================
// HANDLERS ESPECÍFICOS POR TIPO DE EVENTO
// ============================================================================

// HandleEmpresaCreated maneja el evento de creación de empresa
// Responsabilidades:
// 1. Validar que el creador existe o crearlo si no existe
// 2. Asignar rol de EMPRESA_ADMIN al creador
// 3. Manejar errores de duplicación
func (h *EventHandler) HandleEmpresaCreated(payload []byte) error {
	log.Printf("Procesando evento empresa.created: %s", string(payload))

	// Estructura para manejar el formato de mensaje de NestJS/otros frameworks
	type EventWrapper struct {
		Pattern string          `json:"pattern"`
		Data    json.RawMessage `json:"data"`
		Id      string          `json:"id,omitempty"`
	}

	var event EmpresaCreatedEvent

	// Intentar deserializar como wrapper primero
	var wrapper EventWrapper
	if err := json.Unmarshal(payload, &wrapper); err == nil && wrapper.Data != nil {
		// Es un mensaje wrapeado, extraer los datos internos
		if err := json.Unmarshal(wrapper.Data, &event); err != nil {
			log.Printf("Error deserializando datos del wrapper: %v", err)
			return fmt.Errorf("error deserializando datos envueltos: %v", err)
		}
	} else {
		// Intentar deserializar directamente
		if err := json.Unmarshal(payload, &event); err != nil {
			log.Printf("Error deserializando evento directo: %v", err)
			return fmt.Errorf("error deserializando evento: %v", err)
		}
	}

	// Validar datos críticos del evento
	if err := h.validateEmpresaCreatedEvent(&event); err != nil {
		return fmt.Errorf("evento inválido: %v", err)
	}

	// Procesar el evento
	return h.processEmpresaCreatedEvent(&event)
}

// validateEmpresaCreatedEvent valida que el evento tenga los datos necesarios
func (h *EventHandler) validateEmpresaCreatedEvent(event *EmpresaCreatedEvent) error {
	if event.ID == "" {
		return errors.New("ID de empresa requerido")
	}
	if event.CreadorDNI == "" {
		return errors.New("DNI del creador requerido")
	}
	if event.CreadorEmail == "" {
		return errors.New("email del creador requerido")
	}
	if event.CreadorNombres == "" {
		return errors.New("nombres del creador requeridos")
	}

	// Validar formato UUID
	if _, err := uuid.Parse(event.ID); err != nil {
		return fmt.Errorf("ID de empresa inválido: %v", err)
	}

	return nil
}

// processEmpresaCreatedEvent ejecuta la lógica de negocio del evento
func (h *EventHandler) processEmpresaCreatedEvent(event *EmpresaCreatedEvent) error {
	ctx := context.Background()

	// Convertir IDs a UUID
	empresaID, err := uuid.Parse(event.ID)
	if err != nil {
		return fmt.Errorf("error parseando ID de empresa: %v", err)
	}

	// 1. Verificar si el creador ya existe en el sistema
	var creatorUser *entities.User
	
	if event.CreadorID != "" {
		// Si viene el ID, intentar buscarlo
		creatorID, err := uuid.Parse(event.CreadorID)
		if err == nil {
			creatorUser, _ = h.authService.GetUserByID(ctx, creatorID)
		}
	}

	// Si no se encontró por ID, buscar por DNI
	if creatorUser == nil {
		creatorUser, err = h.authService.GetUserByDNI(ctx, event.CreadorDNI)
		if err != nil {
			log.Printf("Creador no encontrado por DNI, creando nuevo usuario: %s", event.CreadorEmail)
			
			// 2. Crear usuario si no existe
			creatorUser, err = h.createUserFromEmpresaEvent(event)
			if err != nil {
				return fmt.Errorf("error creando usuario creador: %v", err)
			}
		}
	}

	// 3. Asignar rol de administrador de empresa
	if err := h.authService.AssignEmpresaAdmin(ctx, creatorUser.ID, empresaID); err != nil {
		// Si el error es porque ya tiene el rol, no es crítico
		if !isAlreadyAssignedError(err) {
			return fmt.Errorf("error asignando rol de empresa admin: %v", err)
		}
		log.Printf("Usuario ya es admin de la empresa %s", empresaID)
	}

	log.Printf("Evento empresa.created procesado exitosamente: empresa=%s, creador=%s", 
		empresaID, creatorUser.ID)

	return nil
}

// createUserFromEmpresaEvent crea un nuevo usuario basado en los datos del evento
func (h *EventHandler) createUserFromEmpresaEvent(event *EmpresaCreatedEvent) (*entities.User, error) {
	ctx := context.Background()

	// Generar contraseña temporal
	tempPassword := generateTempPassword()

	// Separar apellidos si vienen juntos
	apellidoPaterno, apellidoMaterno := splitApellidos(event.CreadorApellidos)

	// Crear usuario con información completa
	user, err := h.authService.Register(
		ctx,
		event.CreadorDNI,
		event.CreadorEmail,
		tempPassword,
		event.CreadorNombres,
		apellidoPaterno,
		apellidoMaterno,
		fmt.Sprintf("%s %s %s", event.CreadorNombres, apellidoPaterno, apellidoMaterno),
		time.Now(), // Fecha de nacimiento por defecto
		event.CreadorTelefono,
		"",  // departamento
		"",  // provincia
		"",  // distrito
		"",  // direccion completa
	)

	if err != nil {
		return nil, err
	}

	// TODO: Enviar email con contraseña temporal
	log.Printf("Usuario creado con contraseña temporal: %s (password: %s)", 
		user.Email, tempPassword)

	return user, nil
}

// HandleUsuarioCreated maneja el evento de creación de usuario en empresa
func (h *EventHandler) HandleUsuarioCreated(payload []byte) error {
	log.Printf("Procesando evento usuario.created: %s", string(payload))

	var event UsuarioCreatedEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("error deserializando evento: %v", err)
	}

	// Validar datos del evento
	if err := h.validateUsuarioCreatedEvent(&event); err != nil {
		return fmt.Errorf("evento inválido: %v", err)
	}

	return h.processUsuarioCreatedEvent(&event)
}

// validateUsuarioCreatedEvent valida el evento de usuario creado
func (h *EventHandler) validateUsuarioCreatedEvent(event *UsuarioCreatedEvent) error {
	if event.DNI == "" || event.Email == "" || event.EmpresaID == "" {
		return errors.New("DNI, email y empresaID son requeridos")
	}

	if _, err := uuid.Parse(event.EmpresaID); err != nil {
		return fmt.Errorf("empresaID inválido: %v", err)
	}

	return nil
}

// processUsuarioCreatedEvent procesa la creación de usuario en empresa
func (h *EventHandler) processUsuarioCreatedEvent(event *UsuarioCreatedEvent) error {
	ctx := context.Background()

	// Convertir IDs
	empresaID, err := uuid.Parse(event.EmpresaID)
	if err != nil {
		return fmt.Errorf("error parseando empresa ID: %v", err)
	}

	// Buscar o crear usuario
	user, err := h.authService.GetUserByDNI(ctx, event.DNI)
	if err != nil {
		// Usuario no existe, crear nuevo
		user, err = h.createUserFromUsuarioEvent(event)
		if err != nil {
			return fmt.Errorf("error creando usuario: %v", err)
		}
	}

	// Determinar rol a asignar
	var roleID uuid.UUID
	if event.RolID != "" {
		roleID, err = uuid.Parse(event.RolID)
		if err != nil {
			return fmt.Errorf("error parseando rol ID: %v", err)
		}
	} else if event.RolName != "" {
		// Buscar rol por nombre
		role, err := h.authService.GetRoleByName(ctx, event.RolName)
		if err != nil {
			return fmt.Errorf("rol no encontrado: %s", event.RolName)
		}
		roleID = role.ID
	} else {
		// Rol por defecto
		role, err := h.authService.GetRoleByName(ctx, "EMPLOYEE")
		if err != nil {
			return fmt.Errorf("rol EMPLOYEE no encontrado: %v", err)
		}
		roleID = role.ID
	}

	// Asignar usuario a empresa con rol
	if err := h.authService.AddUserToEmpresa(ctx, user.ID, empresaID, roleID); err != nil {
		if !isAlreadyAssignedError(err) {
			return fmt.Errorf("error asignando usuario a empresa: %v", err)
		}
	}

	log.Printf("Usuario asignado a empresa exitosamente: user=%s, empresa=%s, rol=%s", 
		user.ID, empresaID, roleID)

	return nil
}

// createUserFromUsuarioEvent crea usuario desde evento de usuario
func (h *EventHandler) createUserFromUsuarioEvent(event *UsuarioCreatedEvent) (*entities.User, error) {
	ctx := context.Background()
	tempPassword := generateTempPassword()

	user, err := h.authService.Register(
		ctx,
		event.DNI,
		event.Email,
		tempPassword,
		event.Nombres,
		event.ApellidoPaterno,
		event.ApellidoMaterno,
		fmt.Sprintf("%s %s %s", event.Nombres, event.ApellidoPaterno, event.ApellidoMaterno),
		time.Now(),
		event.Telefono,
		"", "", "", "",
	)

	if err != nil {
		return nil, err
	}

	log.Printf("Usuario empleado creado: %s (password: %s)", user.Email, tempPassword)
	return user, nil
}

// HandleClienteCreated maneja el evento de creación de cliente
func (h *EventHandler) HandleClienteCreated(payload []byte) error {
	log.Printf("Procesando evento cliente.created: %s", string(payload))

	var event ClienteCreatedEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("error deserializando evento: %v", err)
	}

	// Validar datos del evento
	if err := h.validateClienteCreatedEvent(&event); err != nil {
		return fmt.Errorf("evento inválido: %v", err)
	}

	return h.processClienteCreatedEvent(&event)
}

// validateClienteCreatedEvent valida el evento de cliente creado
func (h *EventHandler) validateClienteCreatedEvent(event *ClienteCreatedEvent) error {
	if event.DNI == "" || event.Email == "" || event.EmpresaID == "" {
		return errors.New("DNI, email y empresaID son requeridos")
	}

	if _, err := uuid.Parse(event.EmpresaID); err != nil {
		return fmt.Errorf("empresaID inválido: %v", err)
	}

	return nil
}

// processClienteCreatedEvent procesa la creación de cliente
func (h *EventHandler) processClienteCreatedEvent(event *ClienteCreatedEvent) error {
	ctx := context.Background()

	// Convertir empresa ID
	empresaID, err := uuid.Parse(event.EmpresaID)
	if err != nil {
		return fmt.Errorf("error parseando empresa ID: %v", err)
	}

	// Buscar o crear usuario
	user, err := h.authService.GetUserByDNI(ctx, event.DNI)
	if err != nil {
		// Cliente no existe, crear nuevo
		user, err = h.createUserFromClienteEvent(event)
		if err != nil {
			return fmt.Errorf("error creando cliente: %v", err)
		}
	}

	// Agregar como cliente a la empresa
	if err := h.authService.AddClientToEmpresa(ctx, user.ID, empresaID); err != nil {
		if !isAlreadyAssignedError(err) {
			return fmt.Errorf("error asignando cliente a empresa: %v", err)
		}
	}

	log.Printf("Cliente asignado a empresa exitosamente: user=%s, empresa=%s", 
		user.ID, empresaID)

	return nil
}

// createUserFromClienteEvent crea usuario desde evento de cliente
func (h *EventHandler) createUserFromClienteEvent(event *ClienteCreatedEvent) (*entities.User, error) {
	ctx := context.Background()
	tempPassword := generateTempPassword()

	user, err := h.authService.Register(
		ctx,
		event.DNI,
		event.Email,
		tempPassword,
		event.Nombres,
		event.ApellidoPaterno,
		event.ApellidoMaterno,
		fmt.Sprintf("%s %s %s", event.Nombres, event.ApellidoPaterno, event.ApellidoMaterno),
		time.Now(),
		event.Telefono,
		"", "", "", "",
	)

	if err != nil {
		return nil, err
	}

	log.Printf("Usuario cliente creado: %s (password: %s)", user.Email, tempPassword)
	return user, nil
}

// ============================================================================
// FUNCIÓN PRINCIPAL DE REGISTRO
// ============================================================================

// RegisterEventHandlers registra todos los manejadores de eventos en el EventBus
func RegisterEventHandlers(eventBus rabbitmq.EventBus, handler *EventHandler) error {
	log.Printf("Registrando manejadores de eventos...")

	// Suscribirse a eventos de creación de empresa
	if err := eventBus.Subscribe("empresa.created", handler.HandleEmpresaCreated); err != nil {
		return fmt.Errorf("error registrando handler empresa.created: %v", err)
	}

	// Suscribirse a eventos de creación de usuario en empresa
	if err := eventBus.Subscribe("usuario.created", handler.HandleUsuarioCreated); err != nil {
		return fmt.Errorf("error registrando handler usuario.created: %v", err)
	}

	// Suscribirse a eventos de creación de cliente
	if err := eventBus.Subscribe("cliente.created", handler.HandleClienteCreated); err != nil {
		return fmt.Errorf("error registrando handler cliente.created: %v", err)
	}

	// Agregar más suscripciones según necesites
	// eventBus.Subscribe("usuario.role.updated", handler.HandleUserRoleUpdated)
	// eventBus.Subscribe("empresa.deleted", handler.HandleEmpresaDeleted)

	log.Printf("Todos los manejadores de eventos registrados exitosamente")
	return nil
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

// generateTempPassword genera una contraseña temporal para usuarios nuevos
func generateTempPassword() string {
	// En producción, usar un generador más seguro
	return fmt.Sprintf("temp_%d", time.Now().Unix())
}

// splitApellidos separa apellidos compuestos en paterno y materno
func splitApellidos(apellidos string) (paterno, materno string) {
	if apellidos == "" {
		return "", ""
	}

	parts := strings.Fields(apellidos)
	if len(parts) >= 2 {
		return parts[0], strings.Join(parts[1:], " ")
	}
	return apellidos, ""
}

// isAlreadyAssignedError verifica si el error es por asignación duplicada
func isAlreadyAssignedError(err error) bool {
	if err == nil {
		return false
	}
	
	errorMsg := err.Error()
	return strings.Contains(errorMsg, "ya tiene") || 
		   strings.Contains(errorMsg, "already") ||
		   strings.Contains(errorMsg, "duplicate")
}

// ============================================================================
// HANDLERS ADICIONALES (PARA FUTURO)
// ============================================================================

// HandleUserRoleUpdated maneja cambios de rol de usuario
func (h *EventHandler) HandleUserRoleUpdated(payload []byte) error {
	// TODO: Implementar cuando sea necesario
	log.Printf("Evento user.role.updated recibido (no implementado): %s", string(payload))
	return nil
}

// HandleEmpresaDeleted maneja eliminación de empresa
func (h *EventHandler) HandleEmpresaDeleted(payload []byte) error {
	// TODO: Implementar cuando sea necesario
	log.Printf("Evento empresa.deleted recibido (no implementado): %s", string(payload))
	return nil
}