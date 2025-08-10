FROM golang:1.21-alpine AS builder

WORKDIR /app

# Instalar dependencias necesarias
RUN apk add --no-cache git

# Copiar archivos de dependencias
COPY go.mod go.sum ./

# Descargar dependencias
RUN go mod download

# Copiar el código fuente
COPY . .

# Compilar la aplicación completa (único binario)
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service .

# Etapa de producción
FROM alpine:latest

WORKDIR /app

# Instalar dependencias necesarias
RUN apk add --no-cache ca-certificates tzdata curl

# Copiar el binario compilado desde la etapa de build
COPY --from=builder /app/auth-service .

# Crear directorios para configuración, estáticos y logs
RUN mkdir -p config static logs && chmod -R 777 logs

# Copiar archivos estáticos y de configuración
COPY static/ ./static/
COPY config/ ./config/

# Exponer puerto
EXPOSE 3007

# Healthcheck básico
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3007/health || exit 1

# Comando para iniciar la aplicación
CMD ["./auth-service"]