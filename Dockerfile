# ============================================================================
# DOCKERFILE PARA AUTH MICROSERVICE - OPTIMIZADO PARA VPS
# ============================================================================

# Etapa 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Instalar dependencias necesarias
RUN apk add --no-cache git ca-certificates

# Copiar go.mod y go.sum
COPY go.mod go.sum ./

# Descargar dependencias
RUN go mod download

# Copiar código fuente
COPY . .

# Compilar binarios estáticos
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o auth-api ./cmd/api/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o auth-worker ./cmd/worker/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o auth-service .

# Etapa 2: Runtime
FROM alpine:3.19

# Instalar dependencias runtime
RUN apk add --no-cache ca-certificates tzdata curl

# Crear usuario no-root
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Crear directorios
RUN mkdir -p config static logs && \
    chown -R appuser:appgroup /app

# Copiar binarios
COPY --from=builder --chown=appuser:appgroup /app/auth-api ./
COPY --from=builder --chown=appuser:appgroup /app/auth-worker ./
COPY --from=builder --chown=appuser:appgroup /app/auth-service ./

# Copiar archivos de configuración
COPY --chown=appuser:appgroup static/ ./static/
COPY --chown=appuser:appgroup config/ ./config/

# Hacer ejecutables
RUN chmod +x ./auth-api ./auth-worker ./auth-service

# 🔥 VARIABLES DE ENTORNO PARA EL MANAGER
ENV GO_ENV=production
ENV AUTH_MODE=both
ENV DOCKER_CONTAINER=true
ENV GIN_MODE=release

# Cambiar a usuario no-root
USER appuser

# Exponer puertos (ajustar según tus servicios)
EXPOSE 3007
EXPOSE 3008

# Health check mejorado
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:3007/health || exit 1

# Comando por defecto
CMD ["./auth-service"]