// main.go (versión mejorada)
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ============================================================================
// VARIABLES GLOBALES Y CONFIGURACIÓN
// ============================================================================

var (
    apiProcess     *os.Process
    workerProcess  *os.Process
    shutdownChan   = make(chan os.Signal, 1)
)

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

func main() {
    log.Println("🚀 Iniciando Auth Microservice Manager...")
    
    // Configurar manejo de señales y logging del sistema
    setupSignalHandling()
    logSystemInfo()
    
    // Defer para cleanup en caso de panic
    defer func() {
        if r := recover(); r != nil {
            log.Printf("🚨 Panic detectado: %v", r)
            performGracefulShutdown()
        }
    }()

    // Determinar modo de ejecución (ENV tiene prioridad sobre CLI args)
    mode := determineRunMode()
    log.Printf("📋 Modo de ejecución: %s", mode)

    switch mode {
    case "api":
        runAPIOnly()
    case "worker":
        runWorkerOnly()
    default:
        runBothProcesses()
    }
}

// ============================================================================
// CONFIGURACIÓN Y UTILIDADES
// ============================================================================

// setupSignalHandling configura el manejo de señales
func setupSignalHandling() {
	log.Printf("🔧 Configurando manejo de señales para %s", runtime.GOOS)
	
	if runtime.GOOS == "windows" {
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		log.Println("🪟 Configuración de señales para Windows aplicada")
	} else {
		signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		log.Println("🐧 Configuración de señales para Unix/Linux aplicada")
	}
}

// logSystemInfo muestra información del sistema
func logSystemInfo() {
	log.Printf("💻 Sistema: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("🐹 Go version: %s", runtime.Version())
	log.Printf("🔢 CPUs disponibles: %d", runtime.NumCPU())
	log.Printf("🔋 PID del proceso principal: %d", os.Getpid())
}

// determineRunMode determina el modo de ejecución (ENV tiene prioridad)
func determineRunMode() string {
    // 1. Verificar variable de entorno primero
    if mode := os.Getenv("AUTH_MODE"); mode != "" {
        log.Printf("📍 Modo desde ENV AUTH_MODE: %s", mode)
        return normalizeMode(mode)
    }
    
    // 2. Verificar argumentos de línea de comandos
    if len(os.Args) > 1 {
        mode := normalizeMode(os.Args[1])
        log.Printf("📍 Modo desde CLI args: %s", mode)
        return mode
    }
    
    // 3. Modo por defecto
    log.Println("📍 Usando modo por defecto: both")
    return "both"
}

// normalizeMode normaliza los diferentes nombres de modo
func normalizeMode(mode string) string {
    switch strings.ToLower(mode) {
    case "api", "server":
        return "api"
    case "worker", "worker-only":
        return "worker"
    case "all", "both":
        return "both"
    default:
        log.Printf("⚠️ Modo desconocido: %s, usando 'both'", mode)
        return "both"
    }
}

// ============================================================================
// MODOS DE EJECUCIÓN
// ============================================================================

// runAPIOnly ejecuta solo el API server
func runAPIOnly() {
    log.Println("🌐 Iniciando solo API Server...")

    cmd := getCommand("api")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        log.Fatalf("❌ Error iniciando API Server: %v", err)
    }

    apiProcess = cmd.Process
    log.Printf("🌐 API Server iniciado con PID: %d", apiProcess.Pid)
    logProcessInfo()

    // Esperar señal de shutdown
    <-shutdownChan
    log.Println("📡 Señal de shutdown recibida")
    performGracefulShutdown()
}

// runWorkerOnly ejecuta solo el worker
func runWorkerOnly() {
    log.Println("⚙️ Iniciando solo Worker...")

    cmd := getCommand("worker")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        log.Fatalf("❌ Error iniciando Worker: %v", err)
    }

    workerProcess = cmd.Process
    log.Printf("⚙️ Worker iniciado con PID: %d", workerProcess.Pid)
    logProcessInfo()

    // Esperar señal de shutdown
    <-shutdownChan
    log.Println("📡 Señal de shutdown recibida")
    performGracefulShutdown()
}

// runBothProcesses ejecuta tanto API como Worker
func runBothProcesses() {
    log.Println("🌐⚙️ Iniciando API + Worker...")

    // Iniciar API Server
    apiCmd := getCommand("api")
    apiCmd.Stdout = os.Stdout
    apiCmd.Stderr = os.Stderr
    if err := apiCmd.Start(); err != nil {
        log.Fatalf("❌ Error iniciando API Server: %v", err)
    }
    apiProcess = apiCmd.Process
    log.Printf("🌐 API Server iniciado con PID: %d", apiProcess.Pid)

    // Dar un momento antes de iniciar el worker
    time.Sleep(1 * time.Second)

    // Iniciar Worker
    workerCmd := getCommand("worker")
    workerCmd.Stdout = os.Stdout
    workerCmd.Stderr = os.Stderr
    if err := workerCmd.Start(); err != nil {
        log.Printf("❌ Error iniciando Worker: %v", err)
        // Si el worker falla, detener el API también
        stopProcessGracefully(apiProcess, "API Server")
        log.Fatal("❌ Terminando debido a error en Worker")
    }
    workerProcess = workerCmd.Process
    log.Printf("⚙️ Worker iniciado con PID: %d", workerProcess.Pid)
    
    logProcessInfo()
    
    // Monitor de procesos en goroutine separada
    go monitorProcesses()

    // Esperar señal de shutdown
    <-shutdownChan
    log.Println("📡 Señal de shutdown recibida")
    performGracefulShutdown()
}

// ============================================================================
// GESTIÓN DE PROCESOS
// ============================================================================

// monitorProcesses verifica que los procesos sigan corriendo
func monitorProcesses() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if apiProcess != nil && !isProcessRunning(apiProcess) {
                log.Printf("⚠️ API Server (PID: %d) se detuvo inesperadamente", apiProcess.Pid)
                // Podrías implementar restart aquí si es necesario
            }
            if workerProcess != nil && !isProcessRunning(workerProcess) {
                log.Printf("⚠️ Worker (PID: %d) se detuvo inesperadamente", workerProcess.Pid)
                // Podrías implementar restart aquí si es necesario
            }
        case <-shutdownChan:
            return
        }
    }
}

// performGracefulShutdown coordina el shutdown de ambos procesos
func performGracefulShutdown() {
	log.Println("🔄 Iniciando shutdown graceful...")
	
	errors := []error{}
	
	// Detener Worker primero (para que deje de procesar eventos)
	if workerProcess != nil {
		log.Println("🔄 Deteniendo Worker...")
		if err := stopProcessGracefully(workerProcess, "Worker"); err != nil {
			errors = append(errors, fmt.Errorf("error deteniendo Worker: %v", err))
		}
		time.Sleep(2 * time.Second)
	}
	
	// Luego detener API Server
	if apiProcess != nil {
		log.Println("🔄 Deteniendo API Server...")
		if err := stopProcessGracefully(apiProcess, "API Server"); err != nil {
			errors = append(errors, fmt.Errorf("error deteniendo API: %v", err))
		}
		time.Sleep(2 * time.Second)
	}
	
	// Verificación final de procesos
	log.Println("🔍 Verificando estado final de procesos...")
	allStopped := true
	
	if workerProcess != nil && isProcessRunning(workerProcess) {
		log.Printf("⚠️ Worker (PID: %d) aún está ejecutándose", workerProcess.Pid)
		allStopped = false
		forceKillProcess(workerProcess, "Worker")
	}
	
	if apiProcess != nil && isProcessRunning(apiProcess) {
		log.Printf("⚠️ API Server (PID: %d) aún está ejecutándose", apiProcess.Pid)
		allStopped = false
		forceKillProcess(apiProcess, "API Server")
	}
	
	// Reportar resultado del shutdown
	if len(errors) > 0 {
		log.Printf("⚠️ Shutdown completado con errores:")
		for _, err := range errors {
			log.Printf("   - %v", err)
		}
	} else if !allStopped {
		log.Println("⚠️ Shutdown completado pero algunos procesos pueden seguir ejecutándose")
	} else {
		log.Println("✅ Shutdown graceful completado exitosamente")
	}
	
	// En Windows, dar tiempo adicional para liberar recursos
	if runtime.GOOS == "windows" {
		log.Println("🪟 Esperando liberación de recursos en Windows...")
		time.Sleep(3 * time.Second)
	}
}

// forceKillProcess intenta terminar un proceso por la fuerza
func forceKillProcess(process *os.Process, name string) {
    log.Printf("🚨 Forzando terminación final de %s (PID: %d)...", name, process.Pid)
    
    if runtime.GOOS == "windows" {
        taskkillCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", process.Pid))
        if err := taskkillCmd.Run(); err != nil {
            log.Printf("⚠️ Error en terminación forzada final de %s: %v", name, err)
        } else {
            log.Printf("✅ %s terminado forzadamente", name)
        }
    } else {
        if err := process.Signal(syscall.SIGKILL); err != nil {
            log.Printf("⚠️ Error enviando SIGKILL a %s: %v", name, err)
        } else {
            log.Printf("✅ %s terminado con SIGKILL", name)
        }
    }
}

// stopProcessGracefully detiene un proceso de forma ordenada
func stopProcessGracefully(process *os.Process, name string) error {
	if process == nil {
		return nil
	}
	
	log.Printf("🛑 Deteniendo %s (PID: %d)...", name, process.Pid)
	
	if runtime.GOOS == "windows" {
		log.Printf("🪟 Intentando terminación suave de %s en Windows...", name)
		
		taskkillCmd := exec.Command("taskkill", "/PID", fmt.Sprintf("%d", process.Pid))
		if err := taskkillCmd.Run(); err != nil {
			log.Printf("⚠️ Taskkill suave falló para %s: %v", name, err)
			
			log.Printf("🪟 Intentando terminación forzada de %s...", name)
			taskkillForceCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", process.Pid))
			if forceErr := taskkillForceCmd.Run(); forceErr != nil {
				log.Printf("⚠️ Taskkill forzado también falló para %s: %v", name, forceErr)
				
				log.Printf("🪟 Usando process.Kill() como último recurso para %s...", name)
				if killErr := process.Kill(); killErr != nil {
					log.Printf("⚠️ process.Kill() también falló para %s: %v", name, killErr)
				}
			}
		}
	} else {
		log.Printf("🐧 Enviando SIGTERM a %s...", name)
		if err := process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("⚠️ Error enviando SIGTERM a %s: %v", name, err)
			if killErr := process.Kill(); killErr != nil {
				log.Printf("⚠️ Error con Kill en %s: %v", name, killErr)
				return killErr
			}
		}
	}
	
	// Esperar que el proceso termine con timeout
	timeout := 15 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 20 * time.Second
	}
	
	return waitForProcessWithTimeout(process, timeout)
}

// logProcessInfo muestra información de los procesos en ejecución
func logProcessInfo() {
	log.Println("📊 Procesos en ejecución:")
	
	if apiProcess != nil {
		log.Printf("   - API Server: PID %d", apiProcess.Pid)
	}
	
	if workerProcess != nil {
		log.Printf("   - Worker: PID %d", workerProcess.Pid)
	}
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================

// isProcessRunning verifica si un proceso está corriendo
func isProcessRunning(process *os.Process) bool {
	if process == nil {
		return false
	}
	
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", process.Pid))
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		outputStr := string(output)
		pidStr := fmt.Sprintf("%d", process.Pid)
		return strings.Contains(outputStr, pidStr) && !strings.Contains(outputStr, "No tasks are running")
	}
	
	return process.Signal(syscall.Signal(0)) == nil
}

// waitForProcessWithTimeout espera que un proceso termine con timeout
func waitForProcessWithTimeout(process *os.Process, timeout time.Duration) error {
	if process == nil {
		return nil
	}
	
	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()
	
	select {
	case err := <-done:
		if err != nil {
			log.Printf("⚠️ Proceso terminó con error: %v", err)
		} else {
			log.Printf("✅ Proceso detenido correctamente")
		}
		return err
	case <-time.After(timeout):
		log.Printf("⚠️ Timeout (%v) esperando que termine el proceso", timeout)
		return fmt.Errorf("timeout esperando que termine el proceso")
	}
}

// logMemoryUsage registra el uso de memoria
// func logMemoryUsage() {
// 	var memStats runtime.MemStats
// 	runtime.ReadMemStats(&memStats)
	
// 	log.Printf("📊 Memoria: Alloc=%.1fMB, Sys=%.1fMB, GC=%d",
// 		float64(memStats.Alloc)/1024/1024,
// 		float64(memStats.Sys)/1024/1024,
// 		memStats.NumGC)
// }

// getCommand retorna el comando apropiado según el entorno (CORREGIDO)
func getCommand(target string) *exec.Cmd {
    goEnv := os.Getenv("GO_ENV")
    
    // 🔥 DETECTAR AUTOMÁTICAMENTE ENTORNO DE PRODUCCIÓN
    isProduction := goEnv == "production" || 
                   os.Getpid() == 1 ||  // Corriendo como PID 1 (Docker)
                   os.Getenv("DOCKER_CONTAINER") == "true" ||
                   isRunningInContainer()

    if isProduction {
        log.Printf("🐳 Detectado entorno de producción, usando ejecutables compilados")
        if target == "api" {
            return exec.Command("./auth-api")
        }
        return exec.Command("./auth-worker")
    }

    // Modo desarrollo - verificar que go esté disponible
    if _, err := exec.LookPath("go"); err != nil {
        log.Printf("⚠️ Go no encontrado en PATH, intentando modo producción como fallback...")
        if target == "api" {
            return exec.Command("./auth-api")
        }
        return exec.Command("./auth-worker")
    }

    log.Printf("🛠️ Modo desarrollo detectado, usando 'go run'")
    if target == "api" {
        return exec.Command("go", "run", "cmd/api/main.go")
    }
    return exec.Command("go", "run", "cmd/worker/main.go")
}

// isRunningInContainer detecta si estamos corriendo en un contenedor
func isRunningInContainer() bool {
    // Verificar archivo /.dockerenv (Docker)
    if _, err := os.Stat("/.dockerenv"); err == nil {
        return true
    }
    
    // Verificar cgroup (Docker/Podman)
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        content := string(data)
        return strings.Contains(content, "docker") || 
               strings.Contains(content, "containerd") ||
               strings.Contains(content, "podman")
    }
    
    return false
}