# Guía de Graceful Shutdown - Auth Microservice

## Problema Resuelto

Este documento describe las mejoras implementadas para resolver los problemas de graceful shutdown en Windows, donde los procesos no se terminaban correctamente y mostraban errores de "Access is denied".

## 🚨 Problemas Resueltos

1. **"Access is denied" en Windows**: Los procesos ahora se terminan usando `taskkill` en lugar de `process.Kill()`
2. **Procesos colgados**: Timeouts extendidos y verificación mejorada
3. **Falta de verificación final**: Ahora verifica que todos los procesos se hayan terminado correctamente
4. **🆕 Procesos persistentes**: Si un proceso no se termina después del timeout, se intenta una terminación forzada adicional
5. **🆕 Health checks continuos**: Los procesos que no se terminan correctamente ya no pueden seguir ejecutando health checks

## 🔍 Problema Específico Resuelto: Health Checks Persistentes

**Síntoma**: Después de hacer `Ctrl+C`, los health checks del worker seguían ejecutándose.

**Causa**: El proceso worker no se terminaba completamente durante el graceful shutdown, quedando en un estado "zombie" donde seguía ejecutando algunas rutinas.

**Solución Implementada**:
1. **Verificación post-timeout**: Después del timeout, se verifica si el proceso sigue ejecutándose
2. **Terminación forzada mejorada**: Si el proceso persiste, se ejecuta `taskkill /F` y se verifica el resultado
3. **Reporte de errores**: Si el proceso no se puede terminar, se reporta como error
4. **Verificación final agresiva**: En `performGracefulShutdown`, se hace una verificación final y se intenta terminar procesos persistentes

## 🔧 Cambios Implementados

### 1. **main.go** - Proceso Principal
- **Terminación mejorada para Windows**: Usa `taskkill` en lugar de `process.Kill()` directamente
- **Estrategia multi-intento**: Terminación suave → Terminación forzada → `process.Kill()`
- **Timeouts extendidos**: 20 segundos para Windows vs 15 segundos para Unix/Linux
- **Verificación de procesos mejorada**: Usa `tasklist` en Windows para verificar si un proceso sigue ejecutándose
- **Tiempo adicional para liberación de recursos**: 3 segundos adicionales en Windows
- **🆕 Terminación forzada mejorada**: Verifica después de `taskkill /F` y reporta errores si el proceso no se termina
- **🆕 Verificación final agresiva**: Si un proceso sigue ejecutándose después del shutdown, intenta terminarlo forzadamente una vez más

- **Unix/Linux**: Mantiene el comportamiento original con `SIGTERM` y `SIGKILL`

### 2. Mejoras en el Worker (`cmd/worker/main.go`)

#### Shutdown Graceful Mejorado
- Timeouts extendidos para Windows (45s vs 30s)
- Mejor manejo de goroutines y recursos
- Tiempo adicional para liberación de recursos
- Recuperación de pánico durante shutdown

### 3. Mejoras en el API Server (`cmd/api/main.go`)

#### HTTP Server Shutdown
- Timeout extendido para Windows (45s vs 30s)
- Mejor logging del proceso de shutdown
- Tiempo adicional para liberación de recursos
- Manejo mejorado de errores de cierre forzado

## Cómo Usar

### Inicio Normal
```bash
# Iniciar ambos servicios
go run main.go

# O iniciar solo el API
go run main.go --mode=api

# O iniciar solo el Worker
go run main.go --mode=worker
```

### Terminación Graceful
1. **Ctrl+C**: Inicia el proceso de shutdown graceful
2. El sistema intentará terminar los procesos de forma ordenada
3. En Windows, usará `taskkill` para mejor compatibilidad
4. Si hay timeout, forzará la terminación

### Logs de Shutdown
Ahora verás logs más detallados durante el shutdown:

```
🛑 Señal de terminación recibida...
🔄 Iniciando shutdown graceful...
🔄 Deteniendo Worker...
🪟 Intentando terminación suave de Worker en Windows...
✅ Worker detenido correctamente
🔄 Deteniendo API Server...
🪟 Intentando terminación suave de API Server en Windows...
✅ API Server detenido correctamente
🔍 Verificando estado final de procesos...
✅ Shutdown graceful completado exitosamente
🪟 Esperando liberación de recursos en Windows...
👋 Auth Microservice terminado correctamente
```

## Solución de Problemas

### Problema: "Access Denied"
**Solución**: El sistema ahora usa `taskkill` en Windows, que tiene mejores permisos que `process.Kill()`

### Problema: Procesos siguen ejecutándose
**Diagnóstico**:
```bash
# Verificar procesos Go ejecutándose
tasklist | findstr go.exe
tasklist | findstr main.exe

# Verificar por PID específico (si lo conoces)
tasklist /FI "PID eq <PID>"
```

**Solución**: Los timeouts extendidos y la verificación final deberían resolver esto

### 🆕 Problema: Health Checks Persistentes
**Síntoma**: Después de `Ctrl+C`, sigues viendo logs como:
```
2025/08/17 05:03:20 main.go:930: ✅ Health check: Todos los servicios saludables
```

**Diagnóstico**:
```bash
# Buscar procesos main.exe
tasklist | findstr main.exe

# Si encuentras un PID, terminarlo manualmente
taskkill /F /PID <PID>
```

**Prevención**: Las mejoras implementadas ahora detectan y terminan estos procesos automáticamente

### Si los Procesos Siguen Ejecutándose
1. **Verificar manualmente**:
   ```cmd
   tasklist | findstr go.exe
   ```

2. **Terminar manualmente si es necesario**:
   ```cmd
   taskkill /F /IM go.exe
   ```

### Si Aparecen Errores de "Access Denied"
- Las nuevas mejoras deberían resolver este problema
- Si persiste, ejecutar como administrador
- Verificar que no hay antivirus bloqueando `taskkill`

### Logs de Error Comunes
- `⚠️ Taskkill suave falló`: Normal, el sistema intentará terminación forzada
- `⚠️ Timeout esperando que termine`: El proceso tomó más tiempo del esperado
- `⚠️ Shutdown completado con errores`: Algunos procesos no se terminaron limpiamente

## Configuración Avanzada

### Ajustar Timeouts
Puedes modificar los timeouts en el código:

```go
// En main.go
timeout := 20 * time.Second // Para Windows

// En cmd/worker/main.go
timeout := 45 * time.Second // Para Windows

// En cmd/api/main.go
ShutdownTimeoutWindows = 45 * time.Second
```

### Variables de Entorno
Puedes configurar el comportamiento usando variables de entorno:

```bash
# Forzar modo de desarrollo
set GO_ENV=development

# Configurar timeouts personalizados (si se implementa)
set SHUTDOWN_TIMEOUT=60
```

## Notas Técnicas

### Diferencias entre Sistemas
- **Windows**: Usa `taskkill` y timeouts extendidos
- **Unix/Linux**: Usa señales del sistema (`SIGTERM`, `SIGKILL`)
- **Verificación de procesos**: `tasklist` en Windows, `Signal(0)` en Unix

### Orden de Terminación
1. Worker (para que deje de procesar eventos)
2. API Server (para que deje de recibir requests)
3. Verificación final de estado
4. Liberación de recursos

### Recuperación de Errores
- Múltiples intentos de terminación
- Fallback a métodos más agresivos
- Logging detallado para debugging
- Continuación del shutdown aunque fallen algunos pasos

Esta implementación debería resolver los problemas de graceful shutdown en Windows y proporcionar una experiencia más robusta en todos los sistemas operativos.