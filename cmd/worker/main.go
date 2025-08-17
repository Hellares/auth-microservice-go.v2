// cmd/worker/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"

	"auth-microservice-go.v2/pkg/api/http/server"
	"auth-microservice-go.v2/pkg/application/services"
	"auth-microservice-go.v2/pkg/infrastructure/email"
	msgHandlers "auth-microservice-go.v2/pkg/infrastructure/messaging/handlers"
	"auth-microservice-go.v2/pkg/infrastructure/messaging/rabbitmq"
)

// ============================================================================
// CONFIGURACIÓN Y VARIABLES GLOBALES
// ============================================================================

var (
	// Canales para coordinar el shutdown graceful
	shutdownChan = make(chan os.Signal, 1)
	//doneChan     = make(chan bool, 1)

	// WaitGroup para esperar que todas las goroutines terminen
	wg sync.WaitGroup
)

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

func main() {
	// Configurar logger con formato detallado
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Iniciando Auth Microservice Worker...")

	// Cargar configuración desde archivos y variables de entorno
	if err := server.LoadConfig(); err != nil {
		log.Fatalf("❌ Error al cargar la configuración: %v", err)
	}
	log.Println("✅ Configuración cargada exitosamente")

	// Conectar a la base de datos
	db, err := server.ConnectDB()
	if err != nil {
		log.Fatalf("❌ Error al conectar a la base de datos: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("⚠️  Error cerrando conexión a BD: %v", err)
		} else {
			log.Println("✅ Conexión a base de datos cerrada")
		}
	}()
	log.Println("✅ Conexión a base de datos establecida")

	// Configurar servicio de email
	emailSender := setupEmailService()
	log.Println("✅ Servicio de email configurado")

	// Inicializar servicios de aplicación
	authService := server.InitializeServices(db, emailSender, db.DB)
	log.Println("✅ Servicios de aplicación inicializados")

	// Configurar manejadores de señales del sistema
	setupSignalHandling()

	// Iniciar worker de eventos de RabbitMQ
	eventBus := startEventWorker(authService)
	defer func() {
		if eventBus != nil {
			if err := eventBus.Close(); err != nil {
				log.Printf("⚠️  Error cerrando EventBus: %v", err)
			} else {
				log.Println("✅ EventBus cerrado correctamente")
			}
		}
	}()

	// Iniciar tareas periódicas de limpieza
	startPeriodicCleanup(db)

	// Iniciar health check interno
	startHealthChecker(db, eventBus)

	log.Println("🎉 Worker iniciado correctamente, procesando eventos...")

	// Esperar señal de terminación
	// <-shutdownChan
	// log.Println("🛑 Señal de terminación recibida, iniciando shutdown graceful...")

		// Mantener el worker corriendo
	for {
	    select {
	    case <-shutdownChan:
	        log.Println("🛑 Señal de terminación recibida...")
	        goto shutdown
	    case <-time.After(1 * time.Minute):
	        logWorkerStats() // Log periódico
	    }
	}

shutdown:
log.Println("🛑 Iniciando shutdown graceful...")

	// Coordinar shutdown graceful
	performGracefulShutdown()

	log.Println("👋 Worker terminado correctamente")
}

// ============================================================================
// CONFIGURACIÓN DE SERVICIOS
// ============================================================================

// setupEmailService configura el servicio de envío de emails
func setupEmailService() *email.SMTPEmailSender {
	emailConfig := email.SMTPConfig{
		Host:     viper.GetString("smtp.host"),
		Port:     viper.GetInt("smtp.port"),
		Username: viper.GetString("smtp.username"),
		Password: viper.GetString("smtp.password"),
		From:     viper.GetString("smtp.from"),
	}

	return email.NewSMTPEmailSender(
		emailConfig,
		viper.GetString("urls.reset_password"),
		viper.GetString("urls.verify_email"),
		viper.GetString("site.name"),
		viper.GetString("site.url"),
		viper.GetString("site.support_email"),
	)
}

// setupSignalHandling configura el manejo de señales del sistema
func setupSignalHandling() {
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
}

// ============================================================================
// WORKER DE EVENTOS RABBITMQ
// ============================================================================

// startEventWorker inicia el worker para procesar eventos de RabbitMQ
// func startEventWorker(authService services.AuthService) rabbitmq.EventBus {
// 	log.Println("🔌 Conectando a RabbitMQ...")

// 	// Conectar a RabbitMQ con reintentos
// 	eventBus, err := connectRabbitMQWithRetry()
// 	if err != nil {
// 		log.Fatalf("❌ Error crítico conectando a RabbitMQ: %v", err)
// 	}

// 	// Inicializar manejadores de eventos
// 	eventHandler := msgHandlers.NewEventHandler(authService)

// 	// Registrar todos los handlers
// 	if err := msgHandlers.RegisterEventHandlers(eventBus, eventHandler); err != nil {
// 		log.Fatalf("❌ Error registrando manejadores de eventos: %v", err)
// 	}

// 	log.Println("✅ Worker de eventos RabbitMQ iniciado correctamente")

// 	// Monitorear estado de conexión en goroutine separada
// 	wg.Add(1)
// 	go monitorRabbitMQConnection(eventBus)

// 	return eventBus
// }

func startEventWorker(authService services.AuthService) rabbitmq.EventBus {
	log.Println("🔌 Conectando a RabbitMQ...")

	// Crear conexión directa sin función auxiliar
	rabbitURL := viper.GetString("rabbitmq.url")
	exchangeName := viper.GetString("rabbitmq.exchange")
	queueName := viper.GetString("rabbitmq.queue")
	
	log.Printf("🔧 Configuración: URL=%s, Exchange=%s, Queue=%s", rabbitURL, exchangeName, queueName)

	eventBus, err := rabbitmq.NewRabbitMQEventBus(rabbitURL, exchangeName, queueName)
	if err != nil {
		log.Fatalf("❌ Error conectando a RabbitMQ: %v", err)
	}

	log.Println("✅ EventBus creado exitosamente")

	// Inicializar manejadores de eventos
	log.Println("🔧 Creando EventHandler...")
	eventHandler := msgHandlers.NewEventHandler(authService)
	log.Println("✅ EventHandler creado")

	// Registrar handlers
	log.Println("📝 Registrando event handlers...")
	if err := msgHandlers.RegisterEventHandlers(eventBus, eventHandler); err != nil {
		log.Fatalf("❌ Error registrando handlers: %v", err)
	}
	log.Println("✅ Event handlers registrados exitosamente")

	log.Println("✅ Worker de eventos RabbitMQ iniciado correctamente")
	return eventBus
}

// connectRabbitMQWithRetry conecta a RabbitMQ con estrategia de reintentos
// func connectRabbitMQWithRetry() (rabbitmq.EventBus, error) {
// 	maxRetries := 5
// 	baseDelay := 2 * time.Second

// 	for attempt := 1; attempt <= maxRetries; attempt++ {
// 		log.Printf("🔄 Intento de conexión a RabbitMQ: %d/%d", attempt, maxRetries)

// 		eventBus, err := rabbitmq.NewRabbitMQEventBus(
// 			viper.GetString("rabbitmq.url"),
// 			viper.GetString("rabbitmq.exchange"),
// 			viper.GetString("rabbitmq.queue"),
// 		)

// 		if err == nil {
// 			log.Println("✅ Conexión a RabbitMQ establecida exitosamente")
// 			log.Println("🎯 DEBUG: Retornando EventBus...")
// 			return eventBus, nil // eventBus ya implementa EventBus correctamente
// 		}

// 		log.Printf("⚠️  Intento %d falló: %v", attempt, err)

// 		if attempt < maxRetries {
// 			delay := time.Duration(attempt) * baseDelay
// 			log.Printf("⏳ Esperando %v antes del siguiente intento...", delay)
// 			time.Sleep(delay)
// 		}
// 	}

// 	return nil, fmt.Errorf("no se pudo conectar a RabbitMQ después de %d intentos", maxRetries)
// }

// monitorRabbitMQConnection monitorea el estado de la conexión RabbitMQ
// func monitorRabbitMQConnection(eventBus rabbitmq.EventBus) {
// 	defer wg.Done()

// 	ticker := time.NewTicker(30 * time.Second)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			if !eventBus.IsConnected() {
// 				log.Println("⚠️  RabbitMQ desconectado, el EventBus manejará la reconexión automáticamente")
// 			} else {
// 				log.Println("✅ RabbitMQ conexión saludable")
// 			}
// 		case <-shutdownChan:
// 			log.Println("🛑 Deteniendo monitor de RabbitMQ...")
// 			return
// 		}
// 	}
// }

// ============================================================================
// TAREAS PERIÓDICAS DE LIMPIEZA
// ============================================================================

// startPeriodicCleanup inicia las tareas de limpieza periódica
func startPeriodicCleanup(db *sqlx.DB) {
	log.Println("🧹 Iniciando tareas de limpieza periódica...")

	// Iniciar limpieza cada hora
	wg.Add(1)
	go runPeriodicCleanup(db)

	// Iniciar limpieza inicial después de 1 minuto
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Minute)
		performCleanupTasks(db)
	}()
}

// runPeriodicCleanup ejecuta tareas de limpieza en intervalos regulares
func runPeriodicCleanup(db *sqlx.DB) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			performCleanupTasks(db)
		case <-shutdownChan:
			log.Println("🛑 Deteniendo tareas de limpieza periódica...")
			return
		}
	}
}

// performCleanupTasks ejecuta todas las tareas de limpieza
func performCleanupTasks(db *sqlx.DB) {
	log.Println("🧹 Ejecutando tareas de limpieza...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Contador de tareas completadas
	tasksCompleted := 0
	totalTasks := 4

	// 1. Limpiar tokens de verificación expirados
	if err := cleanupExpiredVerificationTokens(ctx, db); err != nil {
		log.Printf("❌ Error limpiando tokens de verificación: %v", err)
	} else {
		tasksCompleted++
		log.Println("✅ Tokens de verificación expirados limpiados")
	}

	// 2. Limpiar sesiones expiradas
	if err := cleanupExpiredSessions(ctx, db); err != nil {
		log.Printf("❌ Error limpiando sesiones: %v", err)
	} else {
		tasksCompleted++
		log.Println("✅ Sesiones expiradas limpiadas")
	}

	// 3. Limpiar registros de auditoría antiguos (si existe tabla)
	if err := cleanupOldAuditLogs(ctx, db); err != nil {
		log.Printf("⚠️  Error limpiando logs de auditoría: %v", err)
	} else {
		tasksCompleted++
		log.Println("✅ Logs de auditoría antiguos limpiados")
	}

	// 4. Optimizar estadísticas de base de datos
	if err := optimizeDatabaseStats(ctx, db); err != nil {
		log.Printf("⚠️  Error optimizando estadísticas: %v", err)
	} else {
		tasksCompleted++
		log.Println("✅ Estadísticas de base de datos optimizadas")
	}

	log.Printf("🎯 Limpieza completada: %d/%d tareas exitosas", tasksCompleted, totalTasks)
}

// cleanupExpiredVerificationTokens elimina tokens de verificación expirados
func cleanupExpiredVerificationTokens(ctx context.Context, db *sqlx.DB) error {
	query := `DELETE FROM verification_tokens WHERE expires_at < NOW()`

	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("🗑️  Eliminados %d tokens de verificación expirados", rowsAffected)
	return nil
}

// cleanupExpiredSessions elimina sesiones expiradas
func cleanupExpiredSessions(ctx context.Context, db *sqlx.DB) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`

	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("🗑️  Eliminadas %d sesiones expiradas", rowsAffected)
	return nil
}

// cleanupOldAuditLogs limpia logs de auditoría antiguos (más de 90 días)
func cleanupOldAuditLogs(ctx context.Context, db *sqlx.DB) error {
	// Verificar si existe la tabla de auditoría
	var exists bool
	checkQuery := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_name = 'audit_logs'
		)
	`

	if err := db.QueryRowContext(ctx, checkQuery).Scan(&exists); err != nil {
		return err
	}

	if !exists {
		return nil // Tabla no existe, no hay nada que limpiar
	}

	query := `DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days'`

	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("🗑️  Eliminados %d registros de auditoría antiguos", rowsAffected)
	return nil
}

// optimizeDatabaseStats actualiza estadísticas de PostgreSQL para mejor rendimiento
func optimizeDatabaseStats(ctx context.Context, db *sqlx.DB) error {
	// Actualizar estadísticas de tablas principales
	tables := []string{"users", "sessions", "verification_tokens", "user_empresa_roles"}

	for _, table := range tables {
		query := fmt.Sprintf("ANALYZE %s", table)
		if _, err := db.ExecContext(ctx, query); err != nil {
			log.Printf("⚠️  Error analizando tabla %s: %v", table, err)
		}
	}

	return nil
}

// ============================================================================
// HEALTH CHECKER
// ============================================================================

// startHealthChecker inicia el monitor de salud del worker
func startHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
	log.Println("🏥 Iniciando health checker...")

	wg.Add(1)
	go runHealthChecker(db, eventBus)
}

// runHealthChecker ejecuta checks de salud periódicos
func runHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			performHealthCheck(db, eventBus)
		case <-shutdownChan:
			log.Println("🛑 Deteniendo health checker...")
			return
		}
	}
}

// performHealthCheck ejecuta verificaciones de salud
func performHealthCheck(db *sqlx.DB, eventBus rabbitmq.EventBus) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	healthStatus := map[string]bool{
		"database": false,
		"rabbitmq": false,
	}

	// Check de base de datos
	if err := db.PingContext(ctx); err != nil {
		log.Printf("❌ Health check DB falló: %v", err)
	} else {
		healthStatus["database"] = true
	}

	// Check de RabbitMQ
	if eventBus.IsConnected() {
		healthStatus["rabbitmq"] = true
	} else {
		log.Printf("❌ Health check RabbitMQ falló: desconectado")
	}

	// Reportar estado general
	allHealthy := true
	for _, healthy := range healthStatus {
		if !healthy {
			allHealthy = false
			break
		}
	}

	if allHealthy {
		log.Println("✅ Health check: Todos los servicios saludables")
	} else {
		log.Printf("⚠️  Health check: Estado de servicios: %+v", healthStatus)
	}
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

// performGracefulShutdown coordina el cierre ordenado del worker
func performGracefulShutdown() {
	log.Println("🔄 Iniciando proceso de shutdown graceful...")

	// Timeout para el shutdown
	shutdownTimeout := 30 * time.Second

	// Canal para confirmar que el shutdown terminó
	shutdownDone := make(chan bool, 1)

	// Ejecutar shutdown en goroutine separada
	go func() {
		// Enviar señal de shutdown a todas las goroutines
		close(shutdownChan)

		// Esperar que todas las goroutines terminen
		log.Println("⏳ Esperando que terminen todas las tareas...")
		wg.Wait()

		shutdownDone <- true
	}()

	// Esperar shutdown con timeout
	select {
	case <-shutdownDone:
		log.Println("✅ Shutdown graceful completado exitosamente")
	case <-time.After(shutdownTimeout):
		log.Printf("⚠️  Shutdown timeout (%v) alcanzado, forzando salida", shutdownTimeout)
	}
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

// getWorkerID genera un ID único para esta instancia del worker
func getWorkerID() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return fmt.Sprintf("worker-%s-%d", hostname, os.Getpid())
}

// logWorkerStats registra estadísticas del worker
func logWorkerStats() {
	log.Printf("📊 Worker Stats - Goroutines: %d, PID: %d",
		runtime.NumGoroutine(), os.Getpid())
}
