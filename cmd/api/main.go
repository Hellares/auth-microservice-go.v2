// cmd/api/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/viper"

	// Driver de PostgreSQL
	_ "github.com/lib/pq"

	"auth-microservice-go.v2/pkg/api/http/server"
	"auth-microservice-go.v2/pkg/infrastructure/email"
)

// ============================================================================
// CONFIGURACIÓN Y CONSTANTES
// ============================================================================

const (
	// Timeouts del servidor HTTP
	DefaultReadTimeout  = 15 * time.Second
	DefaultWriteTimeout = 15 * time.Second
	DefaultIdleTimeout  = 60 * time.Second
	
	// Timeout para shutdown graceful (ajustado para Windows)
	ShutdownTimeout        = 30 * time.Second
	ShutdownTimeoutWindows = 45 * time.Second
)

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

// func main() {
//     // Configurar logger con formato detallado
//     log.SetFlags(log.LstdFlags | log.Lshortfile)
//     log.Println("🚀 Iniciando Auth Microservice API Server...")

//     // Cargar configuración desde archivos y variables de entorno
//     if err := server.LoadConfig(); err != nil {
//         log.Fatalf("❌ Error al cargar la configuración: %v", err)
//     }
//     log.Println("✅ Configuración cargada exitosamente")

//     // Conectar a la base de datos
//     db, err := server.ConnectDB()
//     if err != nil {
//         log.Fatalf("❌ Error al conectar a la base de datos: %v", err)
//     }
//     defer func() {
//         if err := db.Close(); err != nil {
//             log.Printf("⚠️  Error cerrando conexión a BD: %v", err)
//         } else {
//             log.Println("✅ Conexión a base de datos cerrada")
//         }
//     }()
//     log.Println("✅ Conexión a base de datos establecida")

//     // Configurar servicio de email
//     emailSender := setupEmailService()
//     log.Println("✅ Servicio de email configurado")

//     // Inicializar servicios de aplicación
//     authService := server.InitializeServices(db, emailSender, db.DB)
//     log.Println("✅ Servicios de aplicación inicializados")

//     // Configurar router HTTP con todos los endpoints
//     router := server.SetupRouter(authService)
//     log.Println("✅ Router HTTP configurado")

//     // Configurar servidor HTTP con timeouts y configuración de producción
//     httpServer := setupHTTPServer(router)

//     // Crear contexto cancelable para controlar goroutines
//     ctx, cancel := context.WithCancel(context.Background())
//     defer cancel()

//     // Iniciar monitoreo de salud con contexto si está en desarrollo
//     if viper.GetString("server.env") == "development" {
//         go startHealthMonitoring(ctx)
//     }

//     // Canal para manejar shutdown graceful
//     shutdownChan := make(chan os.Signal, 1)
//     signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

//     // Iniciar servidor HTTP en goroutine separada
//     serverErrors := make(chan error, 1)
//     go func() {
//         port := getServerPort()
//         log.Printf("🌐 API Server escuchando en puerto %s", port)
//         log.Printf("📍 Health check disponible en: http://localhost:%s/health", port)
//         log.Printf("📋 API docs disponibles en: http://localhost:%s/api/auth", port)

//         // Iniciar servidor
//         if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
//             serverErrors <- fmt.Errorf("error en servidor HTTP: %v", err)
//         }
//     }()

//     // Esperar señal de terminación o error del servidor
//     select {
//     case err := <-serverErrors:
//         log.Fatalf("❌ Error crítico del servidor: %v", err)
//     case sig := <-shutdownChan:
//         log.Printf("🛑 Señal de terminación recibida: %v", sig)

//         // Realizar shutdown graceful
//         cancel() // Detiene goroutines
//         if err := performGracefulShutdown(httpServer); err != nil {
//             log.Printf("⚠️  Error durante shutdown graceful: %v", err)
//         }
//     }

//     log.Println("👋 API Server terminado correctamente")
// }

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    log.Println("🚀 Iniciando Auth Microservice API Server...")

    // Cargar configuración
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
            log.Printf("⚠️ Error cerrando conexión a BD: %v", err)
        } else {
            log.Println("✅ Conexión a base de datos cerrada")
        }
    }()
    log.Println("✅ Conexión a base de datos establecida")

    // ✅ CORRECCIÓN: Inicializar repositorios con prepared statements
    repos, err := server.InitializeRepositories(db)
    if err != nil {
        log.Fatalf("❌ Error inicializando repositorios: %v", err)
    }
    defer func() {
        if err := repos.Close(); err != nil {
            log.Printf("⚠️ Error cerrando repositorios: %v", err)
        } else {
            log.Println("✅ Repositorios cerrados correctamente")
        }
    }()
    log.Println("✅ Repositorios inicializados")

    // Configurar servicio de email
    emailSender := setupEmailService()
    log.Println("✅ Servicio de email configurado")

    // ✅ CORRECCIÓN: Pasar repos en lugar de db
    authService := server.InitializeServices(repos, emailSender, db.DB)
    log.Println("✅ Servicios de aplicación inicializados")

    // Configurar router HTTP
    router := server.SetupRouter(authService)
    log.Println("✅ Router HTTP configurado")

    // Configurar servidor HTTP
    httpServer := setupHTTPServer(router)

    // Crear contexto cancelable
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Monitoreo de salud en desarrollo
    if viper.GetString("server.env") == "development" {
        go startHealthMonitoring(ctx)
    }

    // Canal para shutdown graceful
    shutdownChan := make(chan os.Signal, 1)
    signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

    // Iniciar servidor HTTP
    serverErrors := make(chan error, 1)
    go func() {
        port := getServerPort()
        log.Printf("🌐 API Server escuchando en puerto %s", port)
        log.Printf("🔍 Health check disponible en: http://localhost:%s/health", port)
        log.Printf("📋 API docs disponibles en: http://localhost:%s/api/auth", port)

        if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            serverErrors <- fmt.Errorf("error en servidor HTTP: %v", err)
        }
    }()

    // Esperar señal de terminación o error del servidor
    select {
    case err := <-serverErrors:
        log.Fatalf("❌ Error crítico del servidor: %v", err)
    case sig := <-shutdownChan:
        log.Printf("🛑 Señal de terminación recibida: %v", sig)
        cancel()
        if err := performGracefulShutdown(httpServer); err != nil {
            log.Printf("⚠️ Error durante shutdown graceful: %v", err)
        }
    }

    log.Println("👋 API Server terminado correctamente")
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

// ============================================================================
// CONFIGURACIÓN DEL SERVIDOR HTTP
// ============================================================================

// setupHTTPServer configura el servidor HTTP con timeouts y configuración de producción
func setupHTTPServer(router http.Handler) *http.Server {
	// Obtener timeouts de configuración o usar valores por defecto
	readTimeout := viper.GetDuration("server.read_timeout")
	if readTimeout == 0 {
		readTimeout = DefaultReadTimeout
	}

	writeTimeout := viper.GetDuration("server.write_timeout")
	if writeTimeout == 0 {
		writeTimeout = DefaultWriteTimeout
	}

	idleTimeout := viper.GetDuration("server.idle_timeout")
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}

	// Configurar dirección del servidor
	addr := getServerAddress()

	// Crear servidor con configuración de producción
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		
		// Configuración adicional para producción
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
		
		// Logging de errores del servidor
		ErrorLog: log.New(os.Stderr, "HTTP-SERVER: ", log.LstdFlags),
	}

	log.Printf("🔧 Servidor HTTP configurado:")
	log.Printf("   - Dirección: %s", addr)
	log.Printf("   - Read Timeout: %v", readTimeout)
	log.Printf("   - Write Timeout: %v", writeTimeout)
	log.Printf("   - Idle Timeout: %v", idleTimeout)

	return server
}

// getServerAddress determina la dirección donde escuchará el servidor
func getServerAddress() string {
	port := getServerPort()
	
	// En desarrollo, usar localhost
	if viper.GetString("server.env") == "development" {
		return fmt.Sprintf("localhost:%s", port)
	}
	
	// En producción, escuchar en todas las interfaces
	return fmt.Sprintf(":%s", port)
}

// getServerPort obtiene el puerto del servidor
func getServerPort() string {
	port := viper.GetString("server.port")
	if port == "" {
		port = "8080" // Puerto por defecto
	}
	return port
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================


func performGracefulShutdown(server *http.Server) error {
    log.Println("🔄 Iniciando shutdown graceful del API Server...")

    // Determinar timeout según el sistema operativo
    timeout := ShutdownTimeout
    if runtime.GOOS == "windows" {
        timeout = ShutdownTimeoutWindows
        log.Printf("🪟 Usando timeout extendido para Windows: %v", timeout)
        handleWindowsShutdown() // Llamar a la función específica para Windows
    }

    // Crear contexto con timeout para el shutdown
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    // Detener el servidor de forma ordenada
    log.Println("🛑 Deteniendo servidor HTTP...")
    if err := server.Shutdown(ctx); err != nil {
        log.Printf("❌ Error durante shutdown graceful: %v", err)
        log.Println("🚨 Forzando cierre del servidor...")
        if closeErr := server.Close(); closeErr != nil {
            log.Printf("❌ Error forzando cierre: %v", closeErr)
            return fmt.Errorf("error forzando cierre: %v", closeErr)
        }
        log.Println("⚠️  Servidor cerrado forzadamente")
        return fmt.Errorf("shutdown forzado debido a: %v", err)
    }

    // En Windows, dar tiempo adicional para liberación de recursos
    if runtime.GOOS == "windows" {
        log.Println("🪟 Esperando liberación de recursos del API server en Windows...")
        time.Sleep(2 * time.Second)
    }

    log.Println("✅ API Server detenido correctamente")
    return nil
}

// ============================================================================
// FUNCIONES AUXILIARES Y UTILIDADES
// ============================================================================

// validateConfiguration valida que la configuración esté completa
// func validateConfiguration() error {
// 	// Solo validar si viper ya está configurado
// 	if !viper.IsSet("database.host") {
// 		// En la primera ejecución, viper aún no está configurado
// 		return nil
// 	}

// 	requiredConfigs := map[string]string{
// 		"database.host":     viper.GetString("database.host"),
// 		"database.port":     viper.GetString("database.port"),
// 		"database.user":     viper.GetString("database.user"),
// 		"database.password": viper.GetString("database.password"),
// 		"database.name":     viper.GetString("database.name"),
// 		"auth.jwt_secret":   viper.GetString("auth.jwt_secret"),
// 	}

// 	for key, value := range requiredConfigs {
// 		if value == "" {
// 			return fmt.Errorf("configuración requerida faltante: %s", key)
// 		}
// 	}

// 	// Validar que el JWT secret sea suficientemente seguro
// 	jwtSecret := viper.GetString("auth.jwt_secret")
// 	if len(jwtSecret) < 32 {
// 		return fmt.Errorf("JWT secret debe tener al menos 32 caracteres")
// 	}

// 	return nil
// }

// logServerInfo registra información útil del servidor
// func logServerInfo() {
// 	log.Printf("📋 Información del servidor:")
// 	log.Printf("   - Entorno: %s", viper.GetString("server.env"))
// 	log.Printf("   - Puerto: %s", getServerPort())
// 	log.Printf("   - SO: %s/%s", runtime.GOOS, runtime.GOARCH)
// 	log.Printf("   - Base de datos: %s:%s/%s", 
// 		viper.GetString("database.host"),
// 		viper.GetString("database.port"),
// 		viper.GetString("database.name"))
// 	log.Printf("   - JWT expiration: %s", viper.GetString("auth.token_expiration"))
// 	log.Printf("   - SMTP host: %s", viper.GetString("smtp.host"))
// }

// setupDevelopmentHelpers configura utilidades para desarrollo
// func setupDevelopmentHelpers() {
// 	if viper.GetString("server.env") == "development" {
// 		log.Println("🛠️  Modo desarrollo activado")
// 		// logServerInfo()
		
// 		// En desarrollo, mostrar rutas disponibles
// 		log.Println("📝 Rutas principales disponibles:")
// 		log.Printf("   - POST /api/auth/register")
// 		log.Printf("   - POST /api/auth/login")
// 		log.Printf("   - GET  /api/auth/me")
// 		log.Printf("   - GET  /api/auth/users/me/empresas-optimized")
// 		log.Printf("   - GET  /health")
		
// 		// Mostrar configuración de desarrollo
// 		log.Printf("🔧 Configuración de desarrollo:")
// 		log.Printf("   - Debug mode: %t", viper.GetBool("debug"))
// 		log.Printf("   - Hot reload: %t", viper.GetBool("hot_reload"))
// 	}
// }

// ============================================================================
// HEALTH CHECKS Y MONITORING
// ============================================================================

// startHealthMonitoring inicia monitoreo básico de salud
// func startHealthMonitoring() {
//     // Solo en modo desarrollo
//     if viper.GetString("server.env") != "development" {
//         return
//     }

//     log.Println("💓 Iniciando monitoreo de salud (modo desarrollo)")

//     go func() {
//         ticker := time.NewTicker(5 * time.Minute)
//         defer ticker.Stop()

//         for range ticker.C {
//             logServerStats()
//         }
//     }()
// }

func startHealthMonitoring(ctx context.Context) {
    // Solo en modo desarrollo
    if viper.GetString("server.env") != "development" {
        return
    }

    log.Println("💓 Iniciando monitoreo de salud (modo desarrollo)")

    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            logServerStats()
        case <-ctx.Done():
            log.Println("🛑 Deteniendo monitoreo de salud...")
            return
        }
    }
}
// logServerStats registra estadísticas básicas del servidor
func logServerStats() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	log.Printf("📊 Server Stats:")
	log.Printf("   - Goroutines: %d", runtime.NumGoroutine())
	log.Printf("   - Memory Alloc: %.2f MB", float64(memStats.Alloc)/1024/1024)
	log.Printf("   - Memory Sys: %.2f MB", float64(memStats.Sys)/1024/1024)
	log.Printf("   - GC Cycles: %d", memStats.NumGC)
}

// ============================================================================
// FUNCIONES ESPECÍFICAS PARA WINDOWS
// ============================================================================

// isWindows verifica si estamos ejecutando en Windows
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// handleWindowsShutdown maneja el shutdown específico para Windows
func handleWindowsShutdown() {
	if !isWindows() {
		return
	}
	
	log.Println("🪟 Configuración específica para Windows aplicada")
	// Aquí puedes agregar configuraciones específicas para Windows
}