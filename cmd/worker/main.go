// // cmd/worker/main.go
// package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"os"
// 	"os/signal"
// 	"runtime"
// 	"sync"
// 	"syscall"
// 	"time"

// 	"github.com/jmoiron/sqlx"
// 	_ "github.com/lib/pq"
// 	"github.com/spf13/viper"

// 	"auth-microservice-go.v2/pkg/api/http/server"
// 	"auth-microservice-go.v2/pkg/application/services"
// 	"auth-microservice-go.v2/pkg/infrastructure/email"
// 	msgHandlers "auth-microservice-go.v2/pkg/infrastructure/messaging/handlers"
// 	"auth-microservice-go.v2/pkg/infrastructure/messaging/rabbitmq"
// )

// // ============================================================================
// // CONFIGURACIÓN Y VARIABLES GLOBALES
// // ============================================================================

// var (
// 	// Canales para coordinar el shutdown graceful
// 	shutdownChan = make(chan os.Signal, 1)
// 	//doneChan     = make(chan bool, 1)

// 	// WaitGroup para esperar que todas las goroutines terminen
// 	wg sync.WaitGroup
// )

// // ============================================================================
// // FUNCIÓN PRINCIPAL
// // ============================================================================

// func main() {
// 	// Configurar logger con formato detallado
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	log.Println("🚀 Iniciando Auth Microservice Worker...")

// 	// Cargar configuración desde archivos y variables de entorno
// 	if err := server.LoadConfig(); err != nil {
// 		log.Fatalf("❌ Error al cargar la configuración: %v", err)
// 	}
// 	log.Println("✅ Configuración cargada exitosamente")

// 	// Conectar a la base de datos
// 	db, err := server.ConnectDB()
// 	if err != nil {
// 		log.Fatalf("❌ Error al conectar a la base de datos: %v", err)
// 	}
// 	defer func() {
// 		if err := db.Close(); err != nil {
// 			log.Printf("⚠️  Error cerrando conexión a BD: %v", err)
// 		} else {
// 			log.Println("✅ Conexión a base de datos cerrada")
// 		}
// 	}()
// 	log.Println("✅ Conexión a base de datos establecida")

// 	// Configurar servicio de email
// 	emailSender := setupEmailService()
// 	log.Println("✅ Servicio de email configurado")

// 	// Inicializar servicios de aplicación
// 	authService := server.InitializeServices(db, emailSender, db.DB)
// 	log.Println("✅ Servicios de aplicación inicializados")

// 	// Configurar manejadores de señales del sistema
// 	setupSignalHandling()

// 	// Iniciar worker de eventos de RabbitMQ
// 	eventBus := startEventWorker(authService)
// 	defer func() {
// 		if eventBus != nil {
// 			if err := eventBus.Close(); err != nil {
// 				log.Printf("⚠️  Error cerrando EventBus: %v", err)
// 			} else {
// 				log.Println("✅ EventBus cerrado correctamente")
// 			}
// 		}
// 	}()

// 	// Iniciar tareas periódicas de limpieza
// 	startPeriodicCleanup(db)

// 	// Iniciar health check interno
// 	startHealthChecker(db, eventBus)

// 	log.Println("🎉 Worker iniciado correctamente, procesando eventos...")

// 	// Esperar señal de terminación
// 	// <-shutdownChan
// 	// log.Println("🛑 Señal de terminación recibida, iniciando shutdown graceful...")

// 		// Mantener el worker corriendo
// 	for {
// 	    select {
// 	    case <-shutdownChan:
// 	        log.Println("🛑 Señal de terminación recibida...")
// 	        goto shutdown
// 	    case <-time.After(1 * time.Minute):
// 	        logWorkerStats() // Log periódico
// 	    }
// 	}

// shutdown:
// log.Println("🛑 Iniciando shutdown graceful...")

// 	// Coordinar shutdown graceful
// 	performGracefulShutdown()

// 	log.Println("👋 Worker terminado correctamente")
// }

// // ============================================================================
// // CONFIGURACIÓN DE SERVICIOS
// // ============================================================================

// // setupEmailService configura el servicio de envío de emails
// func setupEmailService() *email.SMTPEmailSender {
// 	emailConfig := email.SMTPConfig{
// 		Host:     viper.GetString("smtp.host"),
// 		Port:     viper.GetInt("smtp.port"),
// 		Username: viper.GetString("smtp.username"),
// 		Password: viper.GetString("smtp.password"),
// 		From:     viper.GetString("smtp.from"),
// 	}

// 	return email.NewSMTPEmailSender(
// 		emailConfig,
// 		viper.GetString("urls.reset_password"),
// 		viper.GetString("urls.verify_email"),
// 		viper.GetString("site.name"),
// 		viper.GetString("site.url"),
// 		viper.GetString("site.support_email"),
// 	)
// }

// // setupSignalHandling configura el manejo de señales del sistema
// func setupSignalHandling() {
// 	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
// }

// // ============================================================================
// // WORKER DE EVENTOS RABBITMQ
// // ============================================================================


// func startEventWorker(authService services.AuthService) rabbitmq.EventBus {
// 	log.Println("🔌 Conectando a RabbitMQ...")

// 	// Crear conexión directa sin función auxiliar
// 	rabbitURL := viper.GetString("rabbitmq.url")
// 	exchangeName := viper.GetString("rabbitmq.exchange")
// 	queueName := viper.GetString("rabbitmq.queue")
	
// 	log.Printf("🔧 Configuración: URL=%s, Exchange=%s, Queue=%s", rabbitURL, exchangeName, queueName)

// 	eventBus, err := rabbitmq.NewRabbitMQEventBus(rabbitURL, exchangeName, queueName)
// 	if err != nil {
// 		log.Fatalf("❌ Error conectando a RabbitMQ: %v", err)
// 	}

// 	log.Println("✅ EventBus creado exitosamente")

// 	// Inicializar manejadores de eventos
// 	log.Println("🔧 Creando EventHandler...")
// 	eventHandler := msgHandlers.NewEventHandler(authService)
// 	log.Println("✅ EventHandler creado")

// 	// Registrar handlers
// 	log.Println("📝 Registrando event handlers...")
// 	if err := msgHandlers.RegisterEventHandlers(eventBus, eventHandler); err != nil {
// 		log.Fatalf("❌ Error registrando handlers: %v", err)
// 	}
// 	log.Println("✅ Event handlers registrados exitosamente")

// 	log.Println("✅ Worker de eventos RabbitMQ iniciado correctamente")
// 	return eventBus
// }


// // ============================================================================
// // TAREAS PERIÓDICAS DE LIMPIEZA
// // ============================================================================

// // startPeriodicCleanup inicia las tareas de limpieza periódica
// func startPeriodicCleanup(db *sqlx.DB) {
// 	log.Println("🧹 Iniciando tareas de limpieza periódica...")

// 	// Iniciar limpieza cada hora
// 	wg.Add(1)
// 	go runPeriodicCleanup(db)

// 	// Iniciar limpieza inicial después de 1 minuto
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		time.Sleep(1 * time.Minute)
// 		performCleanupTasks(db)
// 	}()
// }

// // runPeriodicCleanup ejecuta tareas de limpieza en intervalos regulares
// func runPeriodicCleanup(db *sqlx.DB) {
// 	defer wg.Done()

// 	ticker := time.NewTicker(1 * time.Hour)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			performCleanupTasks(db)
// 		case <-shutdownChan:
// 			log.Println("🛑 Deteniendo tareas de limpieza periódica...")
// 			return
// 		}
// 	}
// }

// // performCleanupTasks ejecuta todas las tareas de limpieza
// func performCleanupTasks(db *sqlx.DB) {
// 	log.Println("🧹 Ejecutando tareas de limpieza...")

// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
// 	defer cancel()

// 	// Contador de tareas completadas
// 	tasksCompleted := 0
// 	totalTasks := 4

// 	// 1. Limpiar tokens de verificación expirados
// 	if err := cleanupExpiredVerificationTokens(ctx, db); err != nil {
// 		log.Printf("❌ Error limpiando tokens de verificación: %v", err)
// 	} else {
// 		tasksCompleted++
// 		log.Println("✅ Tokens de verificación expirados limpiados")
// 	}

// 	// 2. Limpiar sesiones expiradas
// 	if err := cleanupExpiredSessions(ctx, db); err != nil {
// 		log.Printf("❌ Error limpiando sesiones: %v", err)
// 	} else {
// 		tasksCompleted++
// 		log.Println("✅ Sesiones expiradas limpiadas")
// 	}

// 	// 3. Limpiar registros de auditoría antiguos (si existe tabla)
// 	if err := cleanupOldAuditLogs(ctx, db); err != nil {
// 		log.Printf("⚠️  Error limpiando logs de auditoría: %v", err)
// 	} else {
// 		tasksCompleted++
// 		log.Println("✅ Logs de auditoría antiguos limpiados")
// 	}

// 	// 4. Optimizar estadísticas de base de datos
// 	if err := optimizeDatabaseStats(ctx, db); err != nil {
// 		log.Printf("⚠️  Error optimizando estadísticas: %v", err)
// 	} else {
// 		tasksCompleted++
// 		log.Println("✅ Estadísticas de base de datos optimizadas")
// 	}

// 	log.Printf("🎯 Limpieza completada: %d/%d tareas exitosas", tasksCompleted, totalTasks)
// }

// // cleanupExpiredVerificationTokens elimina tokens de verificación expirados
// func cleanupExpiredVerificationTokens(ctx context.Context, db *sqlx.DB) error {
// 	query := `DELETE FROM verification_tokens WHERE expires_at < NOW()`

// 	result, err := db.ExecContext(ctx, query)
// 	if err != nil {
// 		return err
// 	}

// 	rowsAffected, _ := result.RowsAffected()
// 	log.Printf("🗑️  Eliminados %d tokens de verificación expirados", rowsAffected)
// 	return nil
// }

// // cleanupExpiredSessions elimina sesiones expiradas
// func cleanupExpiredSessions(ctx context.Context, db *sqlx.DB) error {
// 	query := `DELETE FROM sessions WHERE expires_at < NOW()`

// 	result, err := db.ExecContext(ctx, query)
// 	if err != nil {
// 		return err
// 	}

// 	rowsAffected, _ := result.RowsAffected()
// 	log.Printf("🗑️  Eliminadas %d sesiones expiradas", rowsAffected)
// 	return nil
// }

// // cleanupOldAuditLogs limpia logs de auditoría antiguos (más de 90 días)
// func cleanupOldAuditLogs(ctx context.Context, db *sqlx.DB) error {
// 	// Verificar si existe la tabla de auditoría
// 	var exists bool
// 	checkQuery := `
// 		SELECT EXISTS (
// 			SELECT 1 FROM information_schema.tables 
// 			WHERE table_name = 'audit_logs'
// 		)
// 	`

// 	if err := db.QueryRowContext(ctx, checkQuery).Scan(&exists); err != nil {
// 		return err
// 	}

// 	if !exists {
// 		return nil // Tabla no existe, no hay nada que limpiar
// 	}

// 	query := `DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days'`

// 	result, err := db.ExecContext(ctx, query)
// 	if err != nil {
// 		return err
// 	}

// 	rowsAffected, _ := result.RowsAffected()
// 	log.Printf("🗑️  Eliminados %d registros de auditoría antiguos", rowsAffected)
// 	return nil
// }

// // optimizeDatabaseStats actualiza estadísticas de PostgreSQL para mejor rendimiento
// func optimizeDatabaseStats(ctx context.Context, db *sqlx.DB) error {
// 	// Actualizar estadísticas de tablas principales
// 	tables := []string{"users", "sessions", "verification_tokens", "user_empresa_roles"}

// 	for _, table := range tables {
// 		query := fmt.Sprintf("ANALYZE %s", table)
// 		if _, err := db.ExecContext(ctx, query); err != nil {
// 			log.Printf("⚠️  Error analizando tabla %s: %v", table, err)
// 		}
// 	}

// 	return nil
// }

// // ============================================================================
// // HEALTH CHECKER
// // ============================================================================

// // startHealthChecker inicia el monitor de salud del worker
// func startHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
// 	log.Println("🏥 Iniciando health checker...")

// 	wg.Add(1)
// 	go runHealthChecker(db, eventBus)
// }

// // runHealthChecker ejecuta checks de salud periódicos
// func runHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
// 	defer wg.Done()

// 	ticker := time.NewTicker(1 * time.Minute)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			performHealthCheck(db, eventBus)
// 		case <-shutdownChan:
// 			log.Println("🛑 Deteniendo health checker...")
// 			return
// 		}
// 	}
// }

// // performHealthCheck ejecuta verificaciones de salud
// func performHealthCheck(db *sqlx.DB, eventBus rabbitmq.EventBus) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	healthStatus := map[string]bool{
// 		"database": false,
// 		"rabbitmq": false,
// 	}

// 	// Check de base de datos
// 	if err := db.PingContext(ctx); err != nil {
// 		log.Printf("❌ Health check DB falló: %v", err)
// 	} else {
// 		healthStatus["database"] = true
// 	}

// 	// Check de RabbitMQ
// 	if eventBus.IsConnected() {
// 		healthStatus["rabbitmq"] = true
// 	} else {
// 		log.Printf("❌ Health check RabbitMQ falló: desconectado")
// 	}

// 	// Reportar estado general
// 	allHealthy := true
// 	for _, healthy := range healthStatus {
// 		if !healthy {
// 			allHealthy = false
// 			break
// 		}
// 	}

// 	if allHealthy {
// 		log.Println("✅ Health check: Todos los servicios saludables")
// 	} else {
// 		log.Printf("⚠️  Health check: Estado de servicios: %+v", healthStatus)
// 	}
// }

// // ============================================================================
// // GRACEFUL SHUTDOWN
// // ============================================================================

// // performGracefulShutdown coordina el cierre ordenado del worker
// func performGracefulShutdown() {
// 	log.Println("🔄 Iniciando proceso de shutdown graceful...")

// 	// Timeout para el shutdown
// 	shutdownTimeout := 30 * time.Second

// 	// Canal para confirmar que el shutdown terminó
// 	shutdownDone := make(chan bool, 1)

// 	// Ejecutar shutdown en goroutine separada
// 	go func() {
// 		// Enviar señal de shutdown a todas las goroutines
// 		close(shutdownChan)

// 		// Esperar que todas las goroutines terminen
// 		log.Println("⏳ Esperando que terminen todas las tareas...")
// 		wg.Wait()

// 		shutdownDone <- true
// 	}()

// 	// Esperar shutdown con timeout
// 	select {
// 	case <-shutdownDone:
// 		log.Println("✅ Shutdown graceful completado exitosamente")
// 	case <-time.After(shutdownTimeout):
// 		log.Printf("⚠️  Shutdown timeout (%v) alcanzado, forzando salida", shutdownTimeout)
// 	}
// }

// // ============================================================================
// // FUNCIONES AUXILIARES
// // ============================================================================

// // getWorkerID genera un ID único para esta instancia del worker
// func getWorkerID() string {
// 	hostname, err := os.Hostname()
// 	if err != nil {
// 		hostname = "unknown"
// 	}

// 	return fmt.Sprintf("worker-%s-%d", hostname, os.Getpid())
// }

// // logWorkerStats registra estadísticas del worker
// func logWorkerStats() {
// 	log.Printf("📊 Worker Stats - Goroutines: %d, PID: %d",
// 		runtime.NumGoroutine(), os.Getpid())
// }


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
	
	// WaitGroup para esperar que todas las goroutines terminen
	wg sync.WaitGroup
	
	// Flag para indicar que el shutdown está en progreso
	isShuttingDown bool
	shutdownMutex  sync.RWMutex
)

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

// func main() {
// 	// Configurar logger con formato detallado
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	log.Println("🚀 Iniciando Auth Microservice Worker...")

// 	// Cargar configuración desde archivos y variables de entorno
// 	if err := server.LoadConfig(); err != nil {
// 		log.Fatalf("❌ Error al cargar la configuración: %v", err)
// 	}
// 	log.Println("✅ Configuración cargada exitosamente")

// 	// Conectar a la base de datos
// 	db, err := server.ConnectDB()
// 	if err != nil {
// 		log.Fatalf("❌ Error al conectar a la base de datos: %v", err)
// 	}
// 	defer func() {
// 		if err := db.Close(); err != nil {
// 			log.Printf("⚠️  Error cerrando conexión a BD: %v", err)
// 		} else {
// 			log.Println("✅ Conexión a base de datos cerrada")
// 		}
// 	}()
// 	log.Println("✅ Conexión a base de datos establecida")

// 	// Configurar servicio de email
// 	emailSender := setupEmailService()
// 	log.Println("✅ Servicio de email configurado")

// 	// Inicializar servicios de aplicación
// 	authService := server.InitializeServices(db, emailSender, db.DB)
// 	log.Println("✅ Servicios de aplicación inicializados")

// 	// Configurar manejadores de señales del sistema (CORREGIDO PARA WINDOWS)
// 	setupSignalHandling()

// 	// Iniciar worker de eventos de RabbitMQ
// 	eventBus := startEventWorker(authService)
// 	defer func() {
// 		if eventBus != nil {
// 			if err := eventBus.Close(); err != nil {
// 				log.Printf("⚠️  Error cerrando EventBus: %v", err)
// 			} else {
// 				log.Println("✅ EventBus cerrado correctamente")
// 			}
// 		}
// 	}()

// 	// Iniciar tareas periódicas de limpieza
// 	startPeriodicCleanup(db)

// 	// Iniciar health check interno
// 	startHealthChecker(db, eventBus)

// 	log.Println("🎉 Worker iniciado correctamente, procesando eventos...")
// 	log.Printf("💡 Worker ID: %s", getWorkerID())
// 	log.Printf("🖥️  Sistema operativo: %s/%s", runtime.GOOS, runtime.GOARCH)

// 	// Mantener el worker corriendo con logs periódicos
// 	mainLoop()

// 	log.Println("👋 Worker terminado correctamente")
// }


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

    // Crear contexto cancelable para controlar goroutines
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

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

    // Iniciar tareas periódicas de limpieza con contexto
    startPeriodicCleanup(ctx, db)

    // Iniciar health check interno con contexto
    startHealthChecker(ctx, db, eventBus)

    log.Println("🎉 Worker iniciado correctamente, procesando eventos...")

    // Mantener el worker corriendo
    for {
        select {
        case <-shutdownChan:
            log.Println("🛑 Señal de terminación recibida...")
            cancel() // Detiene goroutines
            performGracefulShutdown()
            log.Println("👋 Worker terminado correctamente")
            return
        case <-time.After(1 * time.Minute):
            logWorkerStats() // Log periódico
        }
    }
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

// setupSignalHandling configura el manejo de señales del sistema (CORREGIDO)
func setupSignalHandling() {
	log.Printf("🔧 Configurando manejo de señales para %s", runtime.GOOS)
	
	// ✅ CORRECCIÓN PARA WINDOWS
	if runtime.GOOS == "windows" {
		// En Windows, solo usar SIGINT y SIGTERM
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		log.Println("🪟 Configuración de señales para Windows aplicada")
	} else {
		// En Unix/Linux, usar todas las señales
		signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		log.Println("🐧 Configuración de señales para Unix/Linux aplicada")
	}
}

// mainLoop mantiene el worker corriendo y maneja el shutdown
func mainLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case sig := <-shutdownChan:
			log.Printf("🛑 Señal de terminación recibida: %v", sig)
			goto shutdown
		case <-ticker.C:
			// Solo hacer log si no estamos en shutdown
			shutdownMutex.RLock()
			if !isShuttingDown {
				logWorkerStats()
			}
			shutdownMutex.RUnlock()
		}
	}

shutdown:
	log.Println("🛑 Iniciando shutdown graceful...")
	
	// Marcar que estamos en shutdown
	shutdownMutex.Lock()
	isShuttingDown = true
	shutdownMutex.Unlock()
	
	// Coordinar shutdown graceful
	performGracefulShutdown()
}

// ============================================================================
// WORKER DE EVENTOS RABBITMQ
// ============================================================================

// startEventWorker inicia el worker para procesar eventos de RabbitMQ
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

// ============================================================================
// TAREAS PERIÓDICAS DE LIMPIEZA
// ============================================================================

// startPeriodicCleanup inicia las tareas de limpieza periódica
// func startPeriodicCleanup(db *sqlx.DB) {
// 	log.Println("🧹 Iniciando tareas de limpieza periódica...")

// 	// Iniciar limpieza cada hora
// 	wg.Add(1)
// 	go runPeriodicCleanup(db)

// 	// Iniciar limpieza inicial después de 1 minuto
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		select {
// 		case <-time.After(1 * time.Minute):
// 			performCleanupTasks(db)
// 		case <-shutdownChan:
// 			return // Cancelar si recibimos shutdown antes del minuto
// 		}
// 	}()
// }

func startPeriodicCleanup(ctx context.Context, db *sqlx.DB) {
    log.Println("🧹 Iniciando tareas de limpieza periódica...")

    // Iniciar limpieza cada hora
    wg.Add(1)
    go runPeriodicCleanup(ctx, db)

    // Iniciar limpieza inicial después de 1 minuto
    wg.Add(1)
    go func() {
        defer wg.Done()
        time.Sleep(1 * time.Minute)
        performCleanupTasks(db)
    }()
}

// runPeriodicCleanup ejecuta tareas de limpieza en intervalos regulares
// func runPeriodicCleanup(db *sqlx.DB) {
// 	defer wg.Done()

// 	ticker := time.NewTicker(1 * time.Hour)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			shutdownMutex.RLock()
// 			if !isShuttingDown {
// 				performCleanupTasks(db)
// 			}
// 			shutdownMutex.RUnlock()
// 		case <-shutdownChan:
// 			log.Println("🛑 Deteniendo tareas de limpieza periódica...")
// 			return
// 		}
// 	}
// }

func runPeriodicCleanup(ctx context.Context, db *sqlx.DB) {
    defer wg.Done()

    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            performCleanupTasks(db)
        case <-ctx.Done():
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
// func startHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
// 	log.Println("🏥 Iniciando health checker...")

// 	wg.Add(1)
// 	go runHealthChecker(db, eventBus)
// }
func startHealthChecker(ctx context.Context, db *sqlx.DB, eventBus rabbitmq.EventBus) {
    log.Println("🏥 Iniciando health checker...")

    wg.Add(1)
    go runHealthChecker(ctx, db, eventBus)
}
// runHealthChecker ejecuta checks de salud periódicos
// func runHealthChecker(db *sqlx.DB, eventBus rabbitmq.EventBus) {
// 	defer wg.Done()

// 	ticker := time.NewTicker(1 * time.Minute)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			shutdownMutex.RLock()
// 			if !isShuttingDown {
// 				performHealthCheck(db, eventBus)
// 			}
// 			shutdownMutex.RUnlock()
// 		case <-shutdownChan:
// 			log.Println("🛑 Deteniendo health checker...")
// 			return
// 		}
// 	}
// }

func runHealthChecker(ctx context.Context, db *sqlx.DB, eventBus rabbitmq.EventBus) {
    defer wg.Done()

    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            shutdownMutex.RLock()
            if !isShuttingDown {
                performHealthCheck(db, eventBus)
            }
            shutdownMutex.RUnlock()
        case <-ctx.Done():
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
// func performGracefulShutdown() {
// 	log.Println("🔄 Iniciando shutdown graceful del worker...")
	
// 	// Recuperación de pánico durante shutdown
// 	defer func() {
// 		if r := recover(); r != nil {
// 			log.Printf("⚠️  Pánico durante shutdown: %v", r)
// 		}
// 	}()
	
// 	// Marcar que estamos en shutdown
// 	shutdownMutex.Lock()
// 	isShuttingDown = true
// 	shutdownMutex.Unlock()
	
// 	// Crear contexto con timeout para el shutdown (más tiempo en Windows)
// 	timeout := 30 * time.Second
// 	if runtime.GOOS == "windows" {
// 		timeout = 45 * time.Second // Más tiempo en Windows
// 	}
	
// 	ctx, cancel := context.WithTimeout(context.Background(), timeout)
// 	defer cancel()
	
// 	// Canal para coordinar el shutdown de todas las goroutines
// 	shutdownComplete := make(chan struct{})
	
// 	go func() {
// 		defer close(shutdownComplete)
		
// 		// Esperar que todas las goroutines terminen
// 		done := make(chan struct{})
// 		go func() {
// 			wg.Wait()
// 			close(done)
// 		}()
		
// 		// Esperar con timeout (ajustado para Windows)
// 		waitTimeout := 25 * time.Second
// 		if runtime.GOOS == "windows" {
// 			waitTimeout = 35 * time.Second
// 		}
		
// 		select {
// 		case <-done:
// 			log.Println("✅ Todas las tareas completadas exitosamente")
// 		case <-time.After(waitTimeout):
// 			log.Printf("⚠️  Timeout (%v) esperando que terminen las tareas, procediendo con shutdown", waitTimeout)
// 		}
// 	}()
	
// 	// Esperar que el shutdown complete o timeout
// 	select {
// 	case <-shutdownComplete:
// 		log.Println("✅ Shutdown graceful del worker completado")
// 	case <-ctx.Done():
// 		log.Printf("⚠️  Timeout (%v) en shutdown graceful, terminando forzadamente", timeout)
// 	}
	
// 	// En Windows, dar tiempo adicional para liberación de recursos
// 	if runtime.GOOS == "windows" {
// 		log.Println("🪟 Esperando liberación de recursos del worker en Windows...")
// 		time.Sleep(2 * time.Second)
// 	}
	
// 	log.Println("👋 Worker terminado")
// }


func performGracefulShutdown() {
    log.Println("🔄 Iniciando shutdown graceful del worker...")

    // Recuperación de pánico durante shutdown
    defer func() {
        if r := recover(); r != nil {
            log.Printf("⚠️  Pánico durante shutdown: %v", r)
        }
    }()

    // Marcar que estamos en shutdown
    shutdownMutex.Lock()
    isShuttingDown = true
    shutdownMutex.Unlock()

    // Crear contexto con timeout para el shutdown (más tiempo en Windows)
    timeout := 30 * time.Second
    if runtime.GOOS == "windows" {
        timeout = 45 * time.Second // Más tiempo en Windows
    }

    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    // Canal para coordinar el shutdown de todas las goroutines
    shutdownComplete := make(chan struct{})

    go func() {
        defer close(shutdownComplete)

        // Esperar que todas las goroutines terminen
        done := make(chan struct{})
        go func() {
            wg.Wait()
            close(done)
        }()

        // Esperar con timeout (ajustado para Windows)
        waitTimeout := 25 * time.Second
        if runtime.GOOS == "windows" {
            waitTimeout = 35 * time.Second
        }

        select {
        case <-done:
            log.Println("✅ Todas las tareas completadas exitosamente")
        case <-time.After(waitTimeout):
            log.Printf("⚠️  Timeout (%v) esperando que terminen las tareas, procediendo con shutdown", waitTimeout)
        }
    }()

    // Esperar que el shutdown complete o timeout
    select {
    case <-shutdownComplete:
        log.Println("✅ Shutdown graceful del worker completado")
    case <-ctx.Done():
        log.Printf("⚠️  Timeout (%v) en shutdown graceful, terminando forzadamente", timeout)
    }

    // En Windows, dar tiempo adicional para liberación de recursos
    if runtime.GOOS == "windows" {
        log.Println("🪟 Esperando liberación de recursos del worker en Windows...")
        time.Sleep(2 * time.Second)
    }

    log.Println("👋 Worker terminado")
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
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	log.Printf("📊 Worker Stats - Goroutines: %d, PID: %d", 
		runtime.NumGoroutine(), os.Getpid())
	log.Printf("💾 Memory: Alloc=%.1fMB, Sys=%.1fMB, GC=%d",
		float64(memStats.Alloc)/1024/1024,
		float64(memStats.Sys)/1024/1024,
		memStats.NumGC)
}

// isShuttingDownSafe verifica de forma thread-safe si estamos en shutdown
func isShuttingDownSafe() bool {
	shutdownMutex.RLock()
	defer shutdownMutex.RUnlock()
	return isShuttingDown
}