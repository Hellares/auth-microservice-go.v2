// main.go (raíz del proyecto)
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	// "sync"
	"syscall"
	"time"
)

// ============================================================================
// VARIABLES GLOBALES Y CONFIGURACIÓN
// ============================================================================

var (
	// WaitGroup para coordinar procesos
	// wg sync.WaitGroup
	
	// Canales para coordinar shutdown
	shutdownChan = make(chan os.Signal, 1)
	
	// PIDs de los procesos
	apiProcess    *os.Process
	workerProcess *os.Process
)

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Iniciando Auth Microservice...")
	
	// Mostrar información del sistema
	logSystemInfo()
	
	// Determinar modo de ejecución
	mode := determineRunMode()
	log.Printf("🎯 Modo de ejecución: %s", mode)
	
	// Configurar manejo de señales (CORREGIDO PARA WINDOWS)
	setupSignalHandling()
	
	// Ejecutar según el modo
	switch mode {
	case "api":
		runAPIOnly()
	case "worker":
		runWorkerOnly()
	case "all":
		runBothProcesses()
	default:
		log.Fatalf("❌ Modo de ejecución desconocido: %s", mode)
	}
}

// ============================================================================
// CONFIGURACIÓN Y UTILIDADES
// ============================================================================

// setupSignalHandling configura el manejo de señales (CORREGIDO)
func setupSignalHandling() {
	log.Printf("🔧 Configurando manejo de señales para %s", runtime.GOOS)
	
	// ✅ CORRECCIÓN PARA WINDOWS
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
	log.Printf("📋 PID del proceso principal: %d", os.Getpid())
}

// determineRunMode determina el modo de ejecución basado en argumentos
func determineRunMode() string {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "api", "server":
			return "api"
		case "worker", "worker-only":
			return "worker"
		case "all", "both":
			return "all"
		default:
			log.Printf("⚠️  Argumento desconocido: %s, usando modo 'all'", os.Args[1])
		}
	}
	return "all" // Modo por defecto
}

// ============================================================================
// MODOS DE EJECUCIÓN
// ============================================================================

// runAPIOnly ejecuta solo el API server
func runAPIOnly() {
	log.Println("🌐 Iniciando solo API Server...")
	
	cmd := exec.Command("go", "run", "cmd/api/main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Start(); err != nil {
		log.Fatalf("❌ Error iniciando API Server: %v", err)
	}
	
	apiProcess = cmd.Process
	log.Printf("🌐 API Server iniciado con PID: %d", apiProcess.Pid)
	
	// Esperar señal de terminación
	<-shutdownChan
	log.Println("🛑 Señal de terminación recibida...")
	
	// Detener API gracefully
	stopProcessGracefully(apiProcess, "API Server")
	
	log.Println("👋 Auth Microservice terminado correctamente")
}

// runWorkerOnly ejecuta solo el worker
func runWorkerOnly() {
	log.Println("⚙️  Iniciando solo Worker...")
	
	cmd := exec.Command("go", "run", "cmd/worker/main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Start(); err != nil {
		log.Fatalf("❌ Error iniciando Worker: %v", err)
	}
	
	workerProcess = cmd.Process
	log.Printf("⚙️  Worker iniciado con PID: %d", workerProcess.Pid)
	
	// Esperar señal de terminación
	<-shutdownChan
	log.Println("🛑 Señal de terminación recibida...")
	
	// Detener worker gracefully
	stopProcessGracefully(workerProcess, "Worker")
	
	log.Println("👋 Auth Microservice terminado correctamente")
}

// runBothProcesses ejecuta tanto API como Worker
func runBothProcesses() {
	log.Println("🔄 Iniciando API Server y Worker...")
	
	// Iniciar API Server
	apiCmd := exec.Command("go", "run", "cmd/api/main.go")
	apiCmd.Stdout = os.Stdout
	apiCmd.Stderr = os.Stderr
	
	if err := apiCmd.Start(); err != nil {
		log.Fatalf("❌ Error iniciando API Server: %v", err)
	}
	
	apiProcess = apiCmd.Process
	log.Printf("🌐 API Server iniciado con PID: %d", apiProcess.Pid)
	
	// Esperar un poco antes de iniciar el worker
	time.Sleep(2 * time.Second)
	
	// Iniciar Worker
	workerCmd := exec.Command("go", "run", "cmd/worker/main.go")
	workerCmd.Stdout = os.Stdout
	workerCmd.Stderr = os.Stderr
	
	if err := workerCmd.Start(); err != nil {
		log.Fatalf("❌ Error iniciando Worker: %v", err)
	}
	
	workerProcess = workerCmd.Process
	log.Printf("⚙️  Worker iniciado con PID: %d", workerProcess.Pid)
	
	log.Println("✅ API Server y Worker iniciados correctamente")
	
	// Mostrar información de procesos
	logProcessInfo()
	
	log.Println("✅ Microservicio iniciado correctamente")
	log.Println("💡 Presiona Ctrl+C para terminar")
	
	// Esperar señal de terminación
	<-shutdownChan
	log.Println("🛑 Señal de terminación recibida...")
	
	// Coordinar shutdown de ambos procesos
	performGracefulShutdown()
	
	log.Println("👋 Auth Microservice terminado correctamente")
}

// ============================================================================
// GESTIÓN DE PROCESOS
// ============================================================================

// stopProcessGracefully detiene un proceso de forma ordenada (CORREGIDO)
func stopProcessGracefully(process *os.Process, name string) error {
	if process == nil {
		return nil
	}
	
	log.Printf("🛑 Deteniendo %s (PID: %d)...", name, process.Pid)
	
	// ✅ CORRECCIÓN MEJORADA PARA WINDOWS
	if runtime.GOOS == "windows" {
		// En Windows, intentar terminación suave primero usando taskkill
		log.Printf("🪟 Intentando terminación suave de %s en Windows...", name)
		
		// Intentar taskkill /PID primero (terminación suave)
		taskkillCmd := exec.Command("taskkill", "/PID", fmt.Sprintf("%d", process.Pid))
		if err := taskkillCmd.Run(); err != nil {
			log.Printf("⚠️  Taskkill suave falló para %s: %v", name, err)
			
			// Si falla, intentar terminación forzada
			log.Printf("🪟 Intentando terminación forzada de %s...", name)
			taskkillForceCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", process.Pid))
			if forceErr := taskkillForceCmd.Run(); forceErr != nil {
				log.Printf("⚠️  Taskkill forzado también falló para %s: %v", name, forceErr)
				
				// Como último recurso, usar process.Kill()
				log.Printf("🪟 Usando process.Kill() como último recurso para %s...", name)
				if killErr := process.Kill(); killErr != nil {
					log.Printf("⚠️  process.Kill() también falló para %s: %v", name, killErr)
					// No retornar error aquí, continuar con el wait
				}
			}
		}
	} else {
		// En Unix/Linux, usar SIGTERM primero
		log.Printf("🐧 Enviando SIGTERM a %s...", name)
		if err := process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("⚠️  Error enviando SIGTERM a %s: %v", name, err)
			// Si SIGTERM falla, usar Kill
			if killErr := process.Kill(); killErr != nil {
				log.Printf("⚠️  Error con Kill en %s: %v", name, killErr)
				return killErr
			}
		}
	}
	
	// Esperar que el proceso termine con timeout extendido para Windows
	timeout := 15 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 20 * time.Second // Más tiempo en Windows
	}
	
	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()
	
	select {
	case err := <-done:
		if err != nil {
			log.Printf("⚠️  %s terminó con error: %v", name, err)
		} else {
			log.Printf("✅ %s detenido correctamente", name)
		}
		return err
	case <-time.After(timeout):
		log.Printf("⚠️  Timeout (%v) esperando que termine %s", timeout, name)
		
		// Verificar si el proceso aún existe
		if isProcessRunning(process) {
			log.Printf("⚠️  %s aún está ejecutándose después del timeout", name)
			if runtime.GOOS == "windows" {
				// En Windows, intentar taskkill forzado una vez más
				log.Printf("🪟 Último intento con taskkill /F para %s...", name)
				taskkillForceCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", process.Pid))
				if err := taskkillForceCmd.Run(); err != nil {
					log.Printf("⚠️  Taskkill forzado falló: %v", err)
				}
				
				// Esperar un poco y verificar nuevamente
				time.Sleep(2 * time.Second)
				if isProcessRunning(process) {
					log.Printf("⚠️  %s SIGUE ejecutándose después de taskkill /F", name)
					return fmt.Errorf("proceso %s (PID: %d) no pudo ser terminado", name, process.Pid)
				} else {
					log.Printf("✅ %s finalmente terminado con taskkill /F", name)
				}
			} else {
				// En Unix/Linux, usar SIGKILL
				process.Signal(syscall.SIGKILL)
				time.Sleep(1 * time.Second)
				if isProcessRunning(process) {
					return fmt.Errorf("proceso %s (PID: %d) no pudo ser terminado", name, process.Pid)
				}
			}
		} else {
			log.Printf("✅ %s ya no está ejecutándose", name)
		}
		
		return nil
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
		// Dar tiempo para que el worker termine completamente
		time.Sleep(2 * time.Second)
	}
	
	// Luego detener API Server
	if apiProcess != nil {
		log.Println("🔄 Deteniendo API Server...")
		if err := stopProcessGracefully(apiProcess, "API Server"); err != nil {
			errors = append(errors, fmt.Errorf("error deteniendo API: %v", err))
		}
		// Dar tiempo para que el API termine completamente
		time.Sleep(2 * time.Second)
	}
	
	// Verificación final de procesos
	log.Println("🔍 Verificando estado final de procesos...")
	allStopped := true
	
	if workerProcess != nil && isProcessRunning(workerProcess) {
		log.Printf("⚠️  Worker (PID: %d) aún está ejecutándose", workerProcess.Pid)
		allStopped = false
		
		// Intentar terminación forzada final
		log.Printf("🚨 Forzando terminación final del Worker (PID: %d)...", workerProcess.Pid)
		if runtime.GOOS == "windows" {
			taskkillCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", workerProcess.Pid))
			if err := taskkillCmd.Run(); err != nil {
				log.Printf("⚠️  Error en terminación forzada final del Worker: %v", err)
			} else {
				log.Printf("✅ Worker terminado forzadamente")
			}
		}
	}
	
	if apiProcess != nil && isProcessRunning(apiProcess) {
		log.Printf("⚠️  API Server (PID: %d) aún está ejecutándose", apiProcess.Pid)
		allStopped = false
		
		// Intentar terminación forzada final
		log.Printf("🚨 Forzando terminación final del API Server (PID: %d)...", apiProcess.Pid)
		if runtime.GOOS == "windows" {
			taskkillCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", apiProcess.Pid))
			if err := taskkillCmd.Run(); err != nil {
				log.Printf("⚠️  Error en terminación forzada final del API Server: %v", err)
			} else {
				log.Printf("✅ API Server terminado forzadamente")
			}
		}
	}
	
	// Reportar resultado del shutdown
	if len(errors) > 0 {
		log.Printf("⚠️  Shutdown completado con errores:")
		for _, err := range errors {
			log.Printf("   - %v", err)
		}
	} else if !allStopped {
		log.Println("⚠️  Shutdown completado pero algunos procesos pueden seguir ejecutándose")
	} else {
		log.Println("✅ Shutdown graceful completado exitosamente")
	}
	
	// En Windows, dar tiempo adicional para que el sistema libere recursos
	if runtime.GOOS == "windows" {
		log.Println("🪟 Esperando liberación de recursos en Windows...")
		time.Sleep(3 * time.Second)
	}
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
	
	// En Windows, usar tasklist para verificar si el proceso existe
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", process.Pid))
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		// Si el proceso existe, tasklist incluirá el PID en la salida
		// Verificar que la salida contenga el PID y no sea solo el header
		outputStr := string(output)
		pidStr := fmt.Sprintf("%d", process.Pid)
		return strings.Contains(outputStr, pidStr) && !strings.Contains(outputStr, "No tasks are running")
	}
	
	// En Unix/Linux, usar Signal(0)
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
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout esperando que termine el proceso")
	}
}

// logMemoryUsage registra el uso de memoria (solo en desarrollo)
func logMemoryUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	log.Printf("📊 Memoria: Alloc=%.1fMB, Sys=%.1fMB, GC=%d",
		float64(memStats.Alloc)/1024/1024,
		float64(memStats.Sys)/1024/1024,
		memStats.NumGC)
}