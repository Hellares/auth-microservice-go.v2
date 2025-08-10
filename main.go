// main.go - Versión optimizada para producción
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// CONFIGURACIÓN Y CONSTANTES
// ============================================================================

const (
	// Modos de ejecución disponibles
	ModeAll    = "all"
	ModeAPI    = "api"
	ModeWorker = "worker"
	
	// Timeouts
	ShutdownTimeout = 30 * time.Second
	StartupTimeout  = 60 * time.Second
)

// ProcessManager maneja los procesos del microservicio
type ProcessManager struct {
	apiCmd    *exec.Cmd
	workerCmd *exec.Cmd
	mode      string
	mutex     sync.RWMutex
	shutdown  chan os.Signal
	done      chan bool
}

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

func main() {
	// Configurar logger con información detallada
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Iniciando Auth Microservice...")

	// Mostrar información del sistema
	logSystemInfo()

	// Parsear argumentos de línea de comandos
	mode := flag.String("mode", ModeAll, "Modo de ejecución: all, api, worker")
	help := flag.Bool("help", false, "Mostrar ayuda")
	version := flag.Bool("version", false, "Mostrar versión")
	flag.Parse()

	// Manejar flags especiales
	if *help {
		showHelp()
		return
	}

	if *version {
		showVersion()
		return
	}

	// Validar modo de ejecución
	if !isValidMode(*mode) {
		log.Fatalf("❌ Modo inválido: %s. Use 'all', 'api' o 'worker'", *mode)
	}

	// Detectar si estamos en un contenedor Docker
	isDocker := isRunningInDocker()
	if isDocker {
		log.Println("🐳 Detectado entorno Docker")
	}

	// Crear y configurar el manejador de procesos
	pm := &ProcessManager{
		mode:     *mode,
		shutdown: make(chan os.Signal, 1),
		done:     make(chan bool, 1),
	}

	// Configurar manejo de señales del sistema
	signal.Notify(pm.shutdown, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Iniciar los componentes según el modo
	if err := pm.StartComponents(isDocker); err != nil {
		log.Fatalf("❌ Error iniciando componentes: %v", err)
	}

	// Esperar señal de terminación
	log.Println("✅ Microservicio iniciado correctamente")
	log.Println("💡 Presiona Ctrl+C para terminar")
	
	<-pm.shutdown
	log.Println("🛑 Señal de terminación recibida...")

	// Realizar shutdown graceful
	if err := pm.GracefulShutdown(); err != nil {
		log.Printf("⚠️  Error durante shutdown: %v", err)
		os.Exit(1)
	}

	log.Println("👋 Auth Microservice terminado correctamente")
}

// ============================================================================
// GESTIÓN DE PROCESOS
// ============================================================================

// StartComponents inicia los componentes según el modo especificado
func (pm *ProcessManager) StartComponents(isDocker bool) error {
	log.Printf("🎯 Modo de ejecución: %s", pm.mode)

	switch pm.mode {
	case ModeAll:
		return pm.startBothComponents(isDocker)
	case ModeAPI:
		return pm.startAPIOnly(isDocker)
	case ModeWorker:
		return pm.startWorkerOnly(isDocker)
	default:
		return fmt.Errorf("modo no soportado: %s", pm.mode)
	}
}

// startBothComponents inicia tanto el API como el Worker
func (pm *ProcessManager) startBothComponents(isDocker bool) error {
	log.Println("🔄 Iniciando API Server y Worker...")

	// Iniciar API Server
	if err := pm.startAPI(isDocker); err != nil {
		return fmt.Errorf("error iniciando API: %v", err)
	}

	// Esperar un momento para que el API se estabilice
	time.Sleep(2 * time.Second)

	// Iniciar Worker
	if err := pm.startWorker(isDocker); err != nil {
		// Si el worker falla, detener el API también
		pm.stopAPI()
		return fmt.Errorf("error iniciando Worker: %v", err)
	}

	log.Println("✅ API Server y Worker iniciados correctamente")
	pm.logProcessInfo()

	return nil
}

// startAPIOnly inicia solo el API Server
func (pm *ProcessManager) startAPIOnly(isDocker bool) error {
	log.Println("🌐 Iniciando solo API Server...")

	if err := pm.startAPI(isDocker); err != nil {
		return fmt.Errorf("error iniciando API: %v", err)
	}

	log.Println("✅ API Server iniciado correctamente")
	pm.logProcessInfo()

	return nil
}

// startWorkerOnly inicia solo el Worker
func (pm *ProcessManager) startWorkerOnly(isDocker bool) error {
	log.Println("⚙️  Iniciando solo Worker...")

	if err := pm.startWorker(isDocker); err != nil {
		return fmt.Errorf("error iniciando Worker: %v", err)
	}

	log.Println("✅ Worker iniciado correctamente")
	pm.logProcessInfo()

	return nil
}

// startAPI inicia el proceso del API Server
func (pm *ProcessManager) startAPI(isDocker bool) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var cmd *exec.Cmd

	if isDocker {
		// En Docker, usar el binario compilado
		cmd = exec.Command("./auth-api")
	} else {
		// En desarrollo, usar go run si está disponible
		if isGoAvailable() {
			cmd = exec.Command("go", "run", "cmd/api/main.go")
		} else {
			// Fallback: intentar usar binario local si existe
			if _, err := os.Stat("./auth-api"); err == nil {
				cmd = exec.Command("./auth-api")
			} else {
				return fmt.Errorf("ni 'go' ni binario './auth-api' están disponibles")
			}
		}
	}

	pm.apiCmd = cmd
	pm.apiCmd.Stdout = os.Stdout
	pm.apiCmd.Stderr = os.Stderr
	
	// Propagar variables de entorno
	pm.apiCmd.Env = os.Environ()

	// Iniciar proceso
	if err := pm.apiCmd.Start(); err != nil {
		return fmt.Errorf("error iniciando proceso API: %v", err)
	}

	log.Printf("🌐 API Server iniciado con PID: %d", pm.apiCmd.Process.Pid)
	return nil
}

// startWorker inicia el proceso del Worker
func (pm *ProcessManager) startWorker(isDocker bool) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var cmd *exec.Cmd

	if isDocker {
		// En Docker, usar el binario compilado
		cmd = exec.Command("./auth-worker")
	} else {
		// En desarrollo, usar go run si está disponible
		if isGoAvailable() {
			cmd = exec.Command("go", "run", "cmd/worker/main.go")
		} else {
			// Fallback: intentar usar binario local si existe
			if _, err := os.Stat("./auth-worker"); err == nil {
				cmd = exec.Command("./auth-worker")
			} else {
				return fmt.Errorf("ni 'go' ni binario './auth-worker' están disponibles")
			}
		}
	}

	pm.workerCmd = cmd
	pm.workerCmd.Stdout = os.Stdout
	pm.workerCmd.Stderr = os.Stderr
	
	// Propagar variables de entorno
	pm.workerCmd.Env = os.Environ()

	// Iniciar proceso
	if err := pm.workerCmd.Start(); err != nil {
		return fmt.Errorf("error iniciando proceso Worker: %v", err)
	}

	log.Printf("⚙️  Worker iniciado con PID: %d", pm.workerCmd.Process.Pid)
	return nil
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

// GracefulShutdown realiza un cierre ordenado de todos los componentes
func (pm *ProcessManager) GracefulShutdown() error {
	log.Println("🔄 Iniciando shutdown graceful...")

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var errors []error

	// Crear canal para coordinar el shutdown
	shutdownDone := make(chan bool, 1)
	
	// Ejecutar shutdown en goroutine separada
	go func() {
		defer func() { shutdownDone <- true }()

		// Detener Worker primero (procesa eventos)
		if pm.workerCmd != nil && pm.workerCmd.Process != nil {
			if err := pm.stopWorker(); err != nil {
				errors = append(errors, fmt.Errorf("error deteniendo Worker: %v", err))
			}
		}

		// Luego detener API (maneja peticiones HTTP)
		if pm.apiCmd != nil && pm.apiCmd.Process != nil {
			if err := pm.stopAPI(); err != nil {
				errors = append(errors, fmt.Errorf("error deteniendo API: %v", err))
			}
		}
	}()

	// Esperar shutdown con timeout
	select {
	case <-shutdownDone:
		if len(errors) > 0 {
			log.Printf("⚠️  Shutdown completado con errores:")
			for _, err := range errors {
				log.Printf("   - %v", err)
			}
			return fmt.Errorf("shutdown con %d errores", len(errors))
		}
		log.Println("✅ Shutdown graceful completado exitosamente")
		return nil
		
	case <-time.After(ShutdownTimeout):
		log.Printf("⚠️  Timeout de shutdown (%v) alcanzado, forzando terminación", ShutdownTimeout)
		pm.forceKillAll()
		return fmt.Errorf("shutdown timeout")
	}
}

// stopAPI detiene el proceso del API de forma ordenada
func (pm *ProcessManager) stopAPI() error {
	if pm.apiCmd == nil || pm.apiCmd.Process == nil {
		return nil
	}

	pid := pm.apiCmd.Process.Pid
	log.Printf("🛑 Deteniendo API Server (PID: %d)...", pid)

	// Enviar SIGTERM para shutdown graceful
	if err := pm.apiCmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("⚠️  Error enviando SIGTERM al API: %v", err)
		
		// Si falla, intentar SIGKILL
		if killErr := pm.apiCmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("error forzando terminación del API: %v", killErr)
		}
	}

	// Esperar que termine
	if err := pm.apiCmd.Wait(); err != nil {
		log.Printf("⚠️  API terminó con error: %v", err)
	} else {
		log.Println("✅ API Server detenido correctamente")
	}

	pm.apiCmd = nil
	return nil
}

// stopWorker detiene el proceso del Worker de forma ordenada
func (pm *ProcessManager) stopWorker() error {
	if pm.workerCmd == nil || pm.workerCmd.Process == nil {
		return nil
	}

	pid := pm.workerCmd.Process.Pid
	log.Printf("🛑 Deteniendo Worker (PID: %d)...", pid)

	// Enviar SIGTERM para shutdown graceful
	if err := pm.workerCmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("⚠️  Error enviando SIGTERM al Worker: %v", err)
		
		// Si falla, intentar SIGKILL
		if killErr := pm.workerCmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("error forzando terminación del Worker: %v", killErr)
		}
	}

	// Esperar que termine
	if err := pm.workerCmd.Wait(); err != nil {
		log.Printf("⚠️  Worker terminó con error: %v", err)
	} else {
		log.Println("✅ Worker detenido correctamente")
	}

	pm.workerCmd = nil
	return nil
}

// forceKillAll fuerza la terminación de todos los procesos
func (pm *ProcessManager) forceKillAll() {
	if pm.apiCmd != nil && pm.apiCmd.Process != nil {
		log.Printf("🚨 Forzando terminación del API (PID: %d)", pm.apiCmd.Process.Pid)
		pm.apiCmd.Process.Kill()
	}

	if pm.workerCmd != nil && pm.workerCmd.Process != nil {
		log.Printf("🚨 Forzando terminación del Worker (PID: %d)", pm.workerCmd.Process.Pid)
		pm.workerCmd.Process.Kill()
	}
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

// isValidMode verifica si el modo de ejecución es válido
func isValidMode(mode string) bool {
	validModes := []string{ModeAll, ModeAPI, ModeWorker}
	for _, validMode := range validModes {
		if mode == validMode {
			return true
		}
	}
	return false
}

// isRunningInDocker detecta si estamos ejecutando en un contenedor Docker
func isRunningInDocker() bool {
	// Método 1: Verificar archivo .dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Método 2: Verificar cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if len(content) > 0 && (
			// Docker patterns
			contains(content, "docker") ||
			contains(content, "/docker/") ||
			// Kubernetes patterns
			contains(content, "kubepods") ||
			// Container patterns
			contains(content, "container")) {
			return true
		}
	}

	// Método 3: Verificar hostname (contenedores suelen tener hostnames aleatorios)
	hostname, _ := os.Hostname()
	if len(hostname) == 12 || len(hostname) == 64 {
		// Docker containers often have 12-char or 64-char hostnames
		return true
	}

	return false
}

// contains verifica si una cadena contiene una subcadena
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		len(s) > len(substr) && (
			s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			stringContains(s, substr)))
}

// stringContains implementación simple de contains
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// isGoAvailable verifica si el comando 'go' está disponible
func isGoAvailable() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

// logSystemInfo muestra información del sistema
func logSystemInfo() {
	log.Printf("💻 Sistema: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("🐹 Go version: %s", runtime.Version())
	log.Printf("🔢 CPUs disponibles: %d", runtime.NumCPU())
	log.Printf("📋 PID del proceso principal: %d", os.Getpid())
}

// logProcessInfo muestra información de los procesos en ejecución
func (pm *ProcessManager) logProcessInfo() {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	log.Println("📊 Procesos en ejecución:")
	
	if pm.apiCmd != nil && pm.apiCmd.Process != nil {
		log.Printf("   - API Server: PID %d", pm.apiCmd.Process.Pid)
	}
	
	if pm.workerCmd != nil && pm.workerCmd.Process != nil {
		log.Printf("   - Worker: PID %d", pm.workerCmd.Process.Pid)
	}
}

// showHelp muestra la ayuda del programa
func showHelp() {
	fmt.Println("🚀 Auth Microservice")
	fmt.Println()
	fmt.Println("Uso:")
	fmt.Printf("  %s [opciones]\n", os.Args[0])
	fmt.Println()
	fmt.Println("Opciones:")
	fmt.Println("  -mode string")
	fmt.Println("        Modo de ejecución: all, api, worker (default \"all\")")
	fmt.Println("  -help")
	fmt.Println("        Mostrar esta ayuda")
	fmt.Println("  -version")
	fmt.Println("        Mostrar versión")
	fmt.Println()
	fmt.Println("Modos de ejecución:")
	fmt.Println("  all     - Ejecutar API Server y Worker (por defecto)")
	fmt.Println("  api     - Ejecutar solo API Server")
	fmt.Println("  worker  - Ejecutar solo Worker")
	fmt.Println()
	fmt.Println("Ejemplos:")
	fmt.Printf("  %s                    # Ejecutar ambos componentes\n", os.Args[0])
	fmt.Printf("  %s -mode=api          # Solo API Server\n", os.Args[0])
	fmt.Printf("  %s -mode=worker       # Solo Worker\n", os.Args[0])
	fmt.Println()
	fmt.Println("Variables de entorno importantes:")
	fmt.Println("  DATABASE_HOST         - Host de la base de datos")
	fmt.Println("  DATABASE_PORT         - Puerto de la base de datos")
	fmt.Println("  DATABASE_USER         - Usuario de la base de datos")
	fmt.Println("  DATABASE_PASSWORD     - Contraseña de la base de datos")
	fmt.Println("  DATABASE_NAME         - Nombre de la base de datos")
	fmt.Println("  AUTH_JWT_SECRET       - Secreto para tokens JWT")
	fmt.Println("  SERVER_PORT           - Puerto del API Server")
	fmt.Println("  RABBITMQ_URL          - URL de conexión a RabbitMQ")
}

// showVersion muestra la versión del microservicio
func showVersion() {
	fmt.Println("🚀 Auth Microservice")
	fmt.Printf("   Version: %s\n", getVersion())
	fmt.Printf("   Go version: %s\n", runtime.Version())
	fmt.Printf("   Built: %s\n", getBuildTime())
	fmt.Printf("   Git commit: %s\n", getGitCommit())
}

// getVersion retorna la versión del microservicio
func getVersion() string {
	// En producción, esto debería venir de build flags
	return "1.0.0-production"
}

// getBuildTime retorna la fecha de compilación
func getBuildTime() string {
	// En producción, esto debería venir de build flags
	return time.Now().Format("2006-01-02 15:04:05")
}

// getGitCommit retorna el commit de git
func getGitCommit() string {
	// En producción, esto debería venir de build flags
	return "unknown"
}