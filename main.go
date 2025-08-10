// // main.go
// package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"os/signal"
// 	"syscall"
// 	"time"

// 	"github.com/spf13/viper"

// 	"auth-microservice-go.v2/pkg/api/http/server"
// )

// func main() {
// 	// Configurar logger con más información
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	log.Println("🚀 Iniciando Auth Microservice...")

// 	// Cargar configuración
// 	log.Println("📖 Cargando configuración...")
// 	if err := server.LoadConfig(); err != nil {
// 		log.Fatalf("❌ Error al cargar la configuración: %v", err)
// 	}
// 	log.Println("✅ Configuración cargada exitosamente")

// 	// Mostrar configuración (sin datos sensibles)
// 	log.Printf("🔧 Entorno: %s", viper.GetString("server.env"))
// 	log.Printf("🔧 Puerto: %s", viper.GetString("server.port"))
// 	log.Printf("🔧 Base de datos: %s:%s/%s", 
// 		viper.GetString("database.host"),
// 		viper.GetString("database.port"),
// 		viper.GetString("database.name"))

// 	// Intentar conectar a la base de datos (opcional por ahora)
// 	log.Println("🗄️  Intentando conectar a la base de datos...")
// 	db, err := server.ConnectDB()
// 	if err != nil {
// 		log.Printf("⚠️  No se pudo conectar a la base de datos: %v", err)
// 		log.Println("⚠️  Continuando sin base de datos (solo para testing)")
// 		db = nil
// 	} else {
// 		defer db.Close()
// 		log.Println("✅ Conexión a base de datos establecida")
// 	}

// 	// Configurar router
// 	log.Println("🌐 Configurando rutas...")
// 	router := server.SetupRouter()

// 	// TODO: Cuando tengamos repositorios implementados:
// 	// authService := server.InitializeServices(db)
// 	// authHandler := handlers.NewAuthHandler(authService)
// 	// authHandler.RegisterRoutes(router.PathPrefix("/api/auth").Subrouter())

// 	log.Println("✅ Rutas configuradas")

// 	// Configurar servidor HTTP
// 	port := viper.GetString("server.port")
// 	if port == "" {
// 		port = "3007"
// 	}

// 	srv := &http.Server{
// 		Addr:         fmt.Sprintf(":%s", port),
// 		Handler:      router,
// 		ReadTimeout:  viper.GetDuration("server.read_timeout"),
// 		WriteTimeout: viper.GetDuration("server.write_timeout"),
// 		IdleTimeout:  viper.GetDuration("server.idle_timeout"),
// 	}

// 	// Iniciar el servidor en una goroutine
// 	go func() {
// 		log.Printf("🌟 Servidor iniciado en http://localhost:%s", port)
// 		log.Println("📋 Endpoints disponibles:")
// 		log.Println("   GET  /health              - Health check")
// 		log.Println("   GET  /api/auth/test       - Test endpoint")
// 		log.Println("   GET  /email-verified.html - Email verification page")
// 		log.Println("   GET  /static/*            - Static files")
// 		log.Println("")
// 		log.Println("🛑 Presiona Ctrl+C para detener el servidor")
		
// 		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
// 			log.Fatalf("❌ Error al iniciar el servidor: %v", err)
// 		}
// 	}()

// 	// Capturar señales para shutdown graceful
// 	quit := make(chan os.Signal, 1)
// 	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
// 	<-quit
// 	log.Println("🛑 Señal de apagado recibida...")

// 	// Dar tiempo para que se completen las operaciones en curso
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()

// 	log.Println("⏳ Cerrando servidor gracefully...")
// 	if err := srv.Shutdown(ctx); err != nil {
// 		log.Fatalf("❌ Error durante el apagado del servidor: %v", err)
// 	}

// 	log.Println("✅ Servidor cerrado correctamente")
// 	log.Println("👋 ¡Hasta luego!")
// }

// main.go
// package main

// import (
// 	"flag"
// 	"fmt"
// 	"log"
// 	"os"
// 	"os/exec"
// 	"os/signal"
// 	"runtime"
// 	"sync"
// 	"syscall"
// 	"time"
// )

// // ============================================================================
// // CONFIGURACIÓN Y CONSTANTES
// // ============================================================================

// const (
// 	// Modos de ejecución disponibles
// 	ModeAll    = "all"
// 	ModeAPI    = "api"
// 	ModeWorker = "worker"
	
// 	// Timeouts
// 	ShutdownTimeout = 30 * time.Second
// 	StartupTimeout  = 60 * time.Second
// )

// // ProcessManager maneja los procesos del microservicio
// type ProcessManager struct {
// 	apiCmd    *exec.Cmd
// 	workerCmd *exec.Cmd
// 	mode      string
// 	mutex     sync.RWMutex
// 	shutdown  chan os.Signal
// 	done      chan bool
// }

// // ============================================================================
// // FUNCIÓN PRINCIPAL
// // ============================================================================

// func main() {
// 	// Configurar logger con información detallada
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	log.Println("🚀 Iniciando Auth Microservice...")

// 	// Mostrar información del sistema
// 	logSystemInfo()

// 	// Parsear argumentos de línea de comandos
// 	mode := flag.String("mode", ModeAll, "Modo de ejecución: all, api, worker")
// 	help := flag.Bool("help", false, "Mostrar ayuda")
// 	version := flag.Bool("version", false, "Mostrar versión")
// 	flag.Parse()

// 	// Manejar flags especiales
// 	if *help {
// 		showHelp()
// 		return
// 	}

// 	if *version {
// 		showVersion()
// 		return
// 	}

// 	// Validar modo de ejecución
// 	if !isValidMode(*mode) {
// 		log.Fatalf("❌ Modo inválido: %s. Use 'all', 'api' o 'worker'", *mode)
// 	}

// 	// Crear y configurar el manejador de procesos
// 	pm := &ProcessManager{
// 		mode:     *mode,
// 		shutdown: make(chan os.Signal, 1),
// 		done:     make(chan bool, 1),
// 	}

// 	// Configurar manejo de señales del sistema
// 	signal.Notify(pm.shutdown, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

// 	// Iniciar los componentes según el modo
// 	if err := pm.StartComponents(); err != nil {
// 		log.Fatalf("❌ Error iniciando componentes: %v", err)
// 	}

// 	// Esperar señal de terminación
// 	log.Println("✅ Microservicio iniciado correctamente")
// 	log.Println("💡 Presiona Ctrl+C para terminar")
	
// 	<-pm.shutdown
// 	log.Println("🛑 Señal de terminación recibida...")

// 	// Realizar shutdown graceful
// 	if err := pm.GracefulShutdown(); err != nil {
// 		log.Printf("⚠️  Error durante shutdown: %v", err)
// 		os.Exit(1)
// 	}

// 	log.Println("👋 Auth Microservice terminado correctamente")
// }

// // ============================================================================
// // GESTIÓN DE PROCESOS
// // ============================================================================

// // StartComponents inicia los componentes según el modo especificado
// func (pm *ProcessManager) StartComponents() error {
// 	log.Printf("🎯 Modo de ejecución: %s", pm.mode)

// 	switch pm.mode {
// 	case ModeAll:
// 		return pm.startBothComponents()
// 	case ModeAPI:
// 		return pm.startAPIOnly()
// 	case ModeWorker:
// 		return pm.startWorkerOnly()
// 	default:
// 		return fmt.Errorf("modo no soportado: %s", pm.mode)
// 	}
// }

// // startBothComponents inicia tanto el API como el Worker
// func (pm *ProcessManager) startBothComponents() error {
// 	log.Println("🔄 Iniciando API Server y Worker...")

// 	// Iniciar API Server
// 	if err := pm.startAPI(); err != nil {
// 		return fmt.Errorf("error iniciando API: %v", err)
// 	}

// 	// Esperar un momento para que el API se estabilice
// 	time.Sleep(2 * time.Second)

// 	// Iniciar Worker
// 	if err := pm.startWorker(); err != nil {
// 		// Si el worker falla, detener el API también
// 		pm.stopAPI()
// 		return fmt.Errorf("error iniciando Worker: %v", err)
// 	}

// 	log.Println("✅ API Server y Worker iniciados correctamente")
// 	pm.logProcessInfo()

// 	return nil
// }

// // startAPIOnly inicia solo el API Server
// func (pm *ProcessManager) startAPIOnly() error {
// 	log.Println("🌐 Iniciando solo API Server...")

// 	if err := pm.startAPI(); err != nil {
// 		return fmt.Errorf("error iniciando API: %v", err)
// 	}

// 	log.Println("✅ API Server iniciado correctamente")
// 	pm.logProcessInfo()

// 	return nil
// }

// // startWorkerOnly inicia solo el Worker
// func (pm *ProcessManager) startWorkerOnly() error {
// 	log.Println("⚙️  Iniciando solo Worker...")

// 	if err := pm.startWorker(); err != nil {
// 		return fmt.Errorf("error iniciando Worker: %v", err)
// 	}

// 	log.Println("✅ Worker iniciado correctamente")
// 	pm.logProcessInfo()

// 	return nil
// }

// // startAPI inicia el proceso del API Server
// func (pm *ProcessManager) startAPI() error {
// 	pm.mutex.Lock()
// 	defer pm.mutex.Unlock()

// 	// Configurar comando del API
// 	pm.apiCmd = exec.Command("go", "run", "cmd/api/main.go")
// 	pm.apiCmd.Stdout = os.Stdout
// 	pm.apiCmd.Stderr = os.Stderr
	
// 	// Propagar variables de entorno
// 	pm.apiCmd.Env = os.Environ()

// 	// Iniciar proceso
// 	if err := pm.apiCmd.Start(); err != nil {
// 		return fmt.Errorf("error iniciando proceso API: %v", err)
// 	}

// 	log.Printf("🌐 API Server iniciado con PID: %d", pm.apiCmd.Process.Pid)
// 	return nil
// }

// // startWorker inicia el proceso del Worker
// func (pm *ProcessManager) startWorker() error {
// 	pm.mutex.Lock()
// 	defer pm.mutex.Unlock()

// 	// Configurar comando del Worker
// 	pm.workerCmd = exec.Command("go", "run", "cmd/worker/main.go")
// 	pm.workerCmd.Stdout = os.Stdout
// 	pm.workerCmd.Stderr = os.Stderr
	
// 	// Propagar variables de entorno
// 	pm.workerCmd.Env = os.Environ()

// 	// Iniciar proceso
// 	if err := pm.workerCmd.Start(); err != nil {
// 		return fmt.Errorf("error iniciando proceso Worker: %v", err)
// 	}

// 	log.Printf("⚙️  Worker iniciado con PID: %d", pm.workerCmd.Process.Pid)
// 	return nil
// }

// // ============================================================================
// // GRACEFUL SHUTDOWN
// // ============================================================================

// // GracefulShutdown realiza un cierre ordenado de todos los componentes
// func (pm *ProcessManager) GracefulShutdown() error {
// 	log.Println("🔄 Iniciando shutdown graceful...")

// 	pm.mutex.Lock()
// 	defer pm.mutex.Unlock()

// 	var errors []error

// 	// Crear canal para coordinar el shutdown
// 	shutdownDone := make(chan bool, 1)
	
// 	// Ejecutar shutdown en goroutine separada
// 	go func() {
// 		defer func() { shutdownDone <- true }()

// 		// Detener Worker primero (procesa eventos)
// 		if pm.workerCmd != nil && pm.workerCmd.Process != nil {
// 			if err := pm.stopWorker(); err != nil {
// 				errors = append(errors, fmt.Errorf("error deteniendo Worker: %v", err))
// 			}
// 		}

// 		// Luego detener API (maneja peticiones HTTP)
// 		if pm.apiCmd != nil && pm.apiCmd.Process != nil {
// 			if err := pm.stopAPI(); err != nil {
// 				errors = append(errors, fmt.Errorf("error deteniendo API: %v", err))
// 			}
// 		}
// 	}()

// 	// Esperar shutdown con timeout
// 	select {
// 	case <-shutdownDone:
// 		if len(errors) > 0 {
// 			log.Printf("⚠️  Shutdown completado con errores:")
// 			for _, err := range errors {
// 				log.Printf("   - %v", err)
// 			}
// 			return fmt.Errorf("shutdown con %d errores", len(errors))
// 		}
// 		log.Println("✅ Shutdown graceful completado exitosamente")
// 		return nil
		
// 	case <-time.After(ShutdownTimeout):
// 		log.Printf("⚠️  Timeout de shutdown (%v) alcanzado, forzando terminación", ShutdownTimeout)
// 		pm.forceKillAll()
// 		return fmt.Errorf("shutdown timeout")
// 	}
// }

// // stopAPI detiene el proceso del API de forma ordenada
// func (pm *ProcessManager) stopAPI() error {
// 	if pm.apiCmd == nil || pm.apiCmd.Process == nil {
// 		return nil
// 	}

// 	pid := pm.apiCmd.Process.Pid
// 	log.Printf("🛑 Deteniendo API Server (PID: %d)...", pid)

// 	// Enviar SIGTERM para shutdown graceful
// 	if err := pm.apiCmd.Process.Signal(syscall.SIGTERM); err != nil {
// 		log.Printf("⚠️  Error enviando SIGTERM al API: %v", err)
		
// 		// Si falla, intentar SIGKILL
// 		if killErr := pm.apiCmd.Process.Kill(); killErr != nil {
// 			return fmt.Errorf("error forzando terminación del API: %v", killErr)
// 		}
// 	}

// 	// Esperar que termine
// 	if err := pm.apiCmd.Wait(); err != nil {
// 		log.Printf("⚠️  API terminó con error: %v", err)
// 	} else {
// 		log.Println("✅ API Server detenido correctamente")
// 	}

// 	pm.apiCmd = nil
// 	return nil
// }

// // stopWorker detiene el proceso del Worker de forma ordenada
// func (pm *ProcessManager) stopWorker() error {
// 	if pm.workerCmd == nil || pm.workerCmd.Process == nil {
// 		return nil
// 	}

// 	pid := pm.workerCmd.Process.Pid
// 	log.Printf("🛑 Deteniendo Worker (PID: %d)...", pid)

// 	// Enviar SIGTERM para shutdown graceful
// 	if err := pm.workerCmd.Process.Signal(syscall.SIGTERM); err != nil {
// 		log.Printf("⚠️  Error enviando SIGTERM al Worker: %v", err)
		
// 		// Si falla, intentar SIGKILL
// 		if killErr := pm.workerCmd.Process.Kill(); killErr != nil {
// 			return fmt.Errorf("error forzando terminación del Worker: %v", killErr)
// 		}
// 	}

// 	// Esperar que termine
// 	if err := pm.workerCmd.Wait(); err != nil {
// 		log.Printf("⚠️  Worker terminó con error: %v", err)
// 	} else {
// 		log.Println("✅ Worker detenido correctamente")
// 	}

// 	pm.workerCmd = nil
// 	return nil
// }

// // forceKillAll fuerza la terminación de todos los procesos
// func (pm *ProcessManager) forceKillAll() {
// 	if pm.apiCmd != nil && pm.apiCmd.Process != nil {
// 		log.Printf("🚨 Forzando terminación del API (PID: %d)", pm.apiCmd.Process.Pid)
// 		pm.apiCmd.Process.Kill()
// 	}

// 	if pm.workerCmd != nil && pm.workerCmd.Process != nil {
// 		log.Printf("🚨 Forzando terminación del Worker (PID: %d)", pm.workerCmd.Process.Pid)
// 		pm.workerCmd.Process.Kill()
// 	}
// }

// // ============================================================================
// // FUNCIONES AUXILIARES
// // ============================================================================

// // isValidMode verifica si el modo de ejecución es válido
// func isValidMode(mode string) bool {
// 	validModes := []string{ModeAll, ModeAPI, ModeWorker}
// 	for _, validMode := range validModes {
// 		if mode == validMode {
// 			return true
// 		}
// 	}
// 	return false
// }

// // logSystemInfo muestra información del sistema
// func logSystemInfo() {
// 	log.Printf("💻 Sistema: %s/%s", runtime.GOOS, runtime.GOARCH)
// 	log.Printf("🐹 Go version: %s", runtime.Version())
// 	log.Printf("🔢 CPUs disponibles: %d", runtime.NumCPU())
// 	log.Printf("📋 PID del proceso principal: %d", os.Getpid())
// }

// // logProcessInfo muestra información de los procesos en ejecución
// func (pm *ProcessManager) logProcessInfo() {
// 	pm.mutex.RLock()
// 	defer pm.mutex.RUnlock()

// 	log.Println("📊 Procesos en ejecución:")
	
// 	if pm.apiCmd != nil && pm.apiCmd.Process != nil {
// 		log.Printf("   - API Server: PID %d", pm.apiCmd.Process.Pid)
// 	}
	
// 	if pm.workerCmd != nil && pm.workerCmd.Process != nil {
// 		log.Printf("   - Worker: PID %d", pm.workerCmd.Process.Pid)
// 	}
// }

// // showHelp muestra la ayuda del programa
// func showHelp() {
// 	fmt.Println("🚀 Auth Microservice")
// 	fmt.Println()
// 	fmt.Println("Uso:")
// 	fmt.Printf("  %s [opciones]\n", os.Args[0])
// 	fmt.Println()
// 	fmt.Println("Opciones:")
// 	fmt.Println("  -mode string")
// 	fmt.Println("        Modo de ejecución: all, api, worker (default \"all\")")
// 	fmt.Println("  -help")
// 	fmt.Println("        Mostrar esta ayuda")
// 	fmt.Println("  -version")
// 	fmt.Println("        Mostrar versión")
// 	fmt.Println()
// 	fmt.Println("Modos de ejecución:")
// 	fmt.Println("  all     - Ejecutar API Server y Worker (por defecto)")
// 	fmt.Println("  api     - Ejecutar solo API Server")
// 	fmt.Println("  worker  - Ejecutar solo Worker")
// 	fmt.Println()
// 	fmt.Println("Ejemplos:")
// 	fmt.Printf("  %s                    # Ejecutar ambos componentes\n", os.Args[0])
// 	fmt.Printf("  %s -mode=api          # Solo API Server\n", os.Args[0])
// 	fmt.Printf("  %s -mode=worker       # Solo Worker\n", os.Args[0])
// 	fmt.Println()
// 	fmt.Println("Variables de entorno importantes:")
// 	fmt.Println("  DATABASE_HOST         - Host de la base de datos")
// 	fmt.Println("  DATABASE_PORT         - Puerto de la base de datos")
// 	fmt.Println("  DATABASE_USER         - Usuario de la base de datos")
// 	fmt.Println("  DATABASE_PASSWORD     - Contraseña de la base de datos")
// 	fmt.Println("  DATABASE_NAME         - Nombre de la base de datos")
// 	fmt.Println("  AUTH_JWT_SECRET       - Secreto para tokens JWT")
// 	fmt.Println("  SERVER_PORT           - Puerto del API Server")
// 	fmt.Println("  RABBITMQ_URL          - URL de conexión a RabbitMQ")
// }

// // showVersion muestra la versión del microservicio
// func showVersion() {
// 	fmt.Println("🚀 Auth Microservice")
// 	fmt.Printf("   Version: %s\n", getVersion())
// 	fmt.Printf("   Go version: %s\n", runtime.Version())
// 	fmt.Printf("   Built: %s\n", getBuildTime())
// 	fmt.Printf("   Git commit: %s\n", getGitCommit())
// }

// // getVersion retorna la versión del microservicio
// func getVersion() string {
// 	// En producción, esto debería venir de build flags
// 	return "1.0.0-dev"
// }

// // getBuildTime retorna la fecha de compilación
// func getBuildTime() string {
// 	// En producción, esto debería venir de build flags
// 	return time.Now().Format("2006-01-02 15:04:05")
// }

// // getGitCommit retorna el commit de git
// func getGitCommit() string {
// 	// En producción, esto debería venir de build flags
// 	return "unknown"
// }

// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

var startTime = time.Now()

func main() {
	// Configurar logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Iniciando Auth Microservice...")

	// Información del sistema
	logSystemInfo()

	// WaitGroup para coordinar goroutines
	var wg sync.WaitGroup

	// Contexto para cancelar operaciones
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configurar canal para señales del sistema
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	log.Println("🔄 Iniciando API Server y Worker en el mismo proceso...")

	// Iniciar API Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		startAPIServer(ctx)
	}()

	// Iniciar Worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		startWorker(ctx)
	}()

	log.Println("✅ Microservicio iniciado correctamente")
	log.Println("💡 Presiona Ctrl+C para terminar")

	// Esperar señal de terminación
	<-shutdown
	log.Println("🛑 Señal de terminación recibida...")

	// Cancelar contexto para detener todos los componentes
	cancel()

	// Crear timeout para shutdown graceful
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Esperar que todos los componentes terminen
	done := make(chan bool, 1)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		log.Println("✅ Shutdown graceful completado exitosamente")
	case <-shutdownCtx.Done():
		log.Println("⚠️  Timeout de shutdown alcanzado")
	}

	log.Println("👋 Auth Microservice terminado correctamente")
}

// startAPIServer inicia el servidor HTTP API
func startAPIServer(ctx context.Context) {
	log.Println("🌐 Iniciando API Server...")

	// Configurar router
	router := setupRouter()

	// Configurar servidor HTTP
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "3007"
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Iniciar servidor en goroutine
	go func() {
		log.Printf("🌟 API Server iniciado en http://localhost:%s", port)
		log.Println("📋 Endpoints disponibles:")
		log.Println("   GET  /health              - Health check")
		log.Println("   GET  /api/auth/test       - Test endpoint")
		log.Println("   GET  /static/*            - Static files")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Error en API Server: %v", err)
		}
	}()

	// Esperar cancelación del contexto
	<-ctx.Done()
	log.Println("🛑 Deteniendo API Server...")

	// Crear contexto con timeout para shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️  Error durante shutdown del API Server: %v", err)
	} else {
		log.Println("✅ API Server detenido correctamente")
	}
}

// startWorker inicia el componente Worker
func startWorker(ctx context.Context) {
	log.Println("⚙️  Iniciando Worker...")

	// Worker simple - tareas de background
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("✅ Worker iniciado correctamente")

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Deteniendo Worker...")
			log.Println("✅ Worker detenido correctamente")
			return

		case <-ticker.C:
			log.Println("⚙️  Worker: Ejecutando tarea periódica...")
			// Aquí van las tareas del worker como:
			// - Limpiar tokens expirados
			// - Procesar colas de mensajes
			// - Enviar emails pendientes
			// - etc.
		}
	}
}

// setupRouter configura las rutas de la aplicación
func setupRouter() *mux.Router {
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", healthHandler).Methods("GET")

	// API routes
	api := router.PathPrefix("/api").Subrouter()
	auth := api.PathPrefix("/auth").Subrouter()
	
	// Test endpoint
	auth.HandleFunc("/test", testHandler).Methods("GET")

	// Static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	return router
}

// healthHandler maneja el endpoint de health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := fmt.Sprintf(`{
		"status": "ok",
		"timestamp": "%s",
		"service": "auth-microservice",
		"version": "1.0.0",
		"uptime": "%s",
		"pid": %d
	}`, time.Now().UTC().Format(time.RFC3339), getUptime(), os.Getpid())
	
	w.Write([]byte(response))
}

// testHandler maneja el endpoint de prueba
func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := fmt.Sprintf(`{
		"message": "Auth microservice is working!",
		"timestamp": "%s",
		"method": "%s",
		"path": "%s",
		"mode": "single-process",
		"pid": %d
	}`, time.Now().UTC().Format(time.RFC3339), r.Method, r.URL.Path, os.Getpid())
	
	w.Write([]byte(response))
}

// Funciones auxiliares
func getUptime() string {
	return time.Since(startTime).Round(time.Second).String()
}

func logSystemInfo() {
	log.Printf("💻 Sistema: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("🐹 Go version: %s", runtime.Version())
	log.Printf("🔢 CPUs disponibles: %d", runtime.NumCPU())
	log.Printf("📋 PID del proceso: %d", os.Getpid())
	
	// Detectar si estamos en Docker
	if isInDocker() {
		log.Println("🐳 Entorno: Docker Container")
	} else {
		log.Println("🔧 Entorno: Desarrollo")
	}
}

func isInDocker() bool {
	// Verificar archivo /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	
	// Verificar si el PID es 1 (típico en contenedores)
	if os.Getpid() == 1 {
		return true
	}
	
	return false
}