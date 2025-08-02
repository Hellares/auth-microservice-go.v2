# CodeViz Research Context

> **Note**: This file contains research context from CodeViz. Most recent contexts are at the bottom.

---

## Research Query

puedes darme la estructura en forma de arbol para mejor legibilidad

*Session: 1106687135c678e677feb8439c7ad4c5 | Generated: 7/29/2025, 3:44:12 AM*

### Analysis Summary

# Estructura del Microservicio de Autenticación (auth-microservice-go.v2)

Este microservicio de autenticación en Go sigue una estructura modular, separando las responsabilidades en diferentes paquetes para una mejor organización y mantenibilidad.

## Estructura de Directorios

```
c:/Users/USER/Desktop/auth-microservice-go.v2/
├───auth-microservice-go.v2.exe  // Ejecutable compilado del microservicio.
├───go.mod                       // Define el módulo y sus dependencias.
├───go.sum                       // Contiene los hashes de las dependencias para verificación.
├───main.go                      // Punto de entrada principal de la aplicación.
├───cmd/                         // Contiene los puntos de entrada para diferentes ejecutables o modos de operación.
│   ├───api/                     // Punto de entrada para la API HTTP principal.
│   └───worker/                  // Punto de entrada para procesos de worker o tareas en segundo plano.
├───config/                      // Almacena archivos de configuración de la aplicación.
│   └───config.yaml              // Archivo de configuración principal en formato YAML.
├───pkg/                         // Contiene el código fuente de los paquetes internos reutilizables.
│   ├───api/                     // Lógica relacionada con la capa de API.
│   │   └───http/                // Implementación de la API HTTP.
│   │       ├───handlers/        // Manejadores de las rutas HTTP (controladores).
│   │       └───server/          // Configuración y arranque del servidor HTTP.
│   │           └───[server.go](pkg/api/http/server/server.go) // Define el servidor HTTP.
│   ├───application/             // Contiene la lógica de negocio de la aplicación (casos de uso).
│   │   ├───ports/               // Interfaces que definen los servicios externos requeridos por la aplicación.
│   │   │   └───[email_sender.go](pkg/application/ports/email_sender.go) // Interfaz para el envío de correos electrónicos.
│   │   └───services/            // Implementaciones de los servicios de la aplicación.
│   │       ├───[auth_service_impl.go](pkg/application/services/auth_service_impl.go) // Implementación del servicio de autenticación.
│   │       └───[auth_service.go](pkg/application/services/auth_service.go) // Interfaz del servicio de autenticación.
│   ├───domain/                  // Define el modelo de dominio (entidades y repositorios).
│   │   ├───entities/            // Estructuras de datos que representan los objetos de negocio.
│   │   │   ├───[permission.go](pkg/domain/entities/permission.go) // Entidad de permiso.
│   │   │   ├───[role.go](pkg/domain/entities/role.go)             // Entidad de rol.
│   │   │   ├───[session.go](pkg/domain/entities/session.go)       // Entidad de sesión.
│   │   │   ├───[system_role.go](pkg/domain/entities/system_role.go) // Entidad de rol de sistema.
│   │   │   ├───[user_empresa_role.go](pkg/domain/entities/user_empresa_role.go) // Entidad de rol de usuario por empresa.
│   │   │   ├───[user.go](pkg/domain/entities/user.go)             // Entidad de usuario.
│   │   │   └───[verification_token.go](pkg/domain/entities/verification_token.go) // Entidad de token de verificación.
│   │   └───repositories/        // Interfaces que definen las operaciones de persistencia para las entidades.
│   │       ├───[permission_repository.go](pkg/domain/repositories/permission_repository.go) // Repositorio de permisos.
│   │       ├───[role_repository.go](pkg/domain/repositories/role_repository.go)             // Repositorio de roles.
│   │       ├───[session_repository.go](pkg/domain/repositories/session_repository.go)       // Repositorio de sesiones.
│   │       ├───[system_role_repository.go](pkg/domain/repositories/system_role_repository.go) // Repositorio de roles de sistema.
│   │       ├───[user_empresa_role_repository.go](pkg/domain/repositories/user_empresa_role_repository.go) // Repositorio de roles de usuario por empresa.
│   │       ├───[user_repository.go](pkg/domain/repositories/user_repository.go)             // Repositorio de usuarios.
│   │       └───[verification_token_repository.go](pkg/domain/repositories/verification_token_repository.go) // Repositorio de tokens de verificación.
│   └───infrastructure/          // Implementaciones concretas de los puertos y repositorios.
│       ├───auth/                // Implementaciones relacionadas con la autenticación (e.g., JWT).
│       │   └───[jwt_service.go](pkg/infrastructure/auth/jwt_service.go) // Servicio para la gestión de JWT.
│       ├───email/               // Implementaciones para el envío de correos electrónicos.
│       │   └───[smtp_email_sender.go](pkg/infrastructure/email/smtp_email_sender.go) // Implementación de envío de correo vía SMTP.
│       ├───messaging/           // Implementaciones para la mensajería (e.g., RabbitMQ).
│       │   ├───handlers/        // Manejadores de mensajes.
│       │   └───rabbitmq/        // Implementación específica de RabbitMQ.
│       └───persistence/         // Implementaciones de los repositorios de persistencia.
│           └───postgres/        // Implementaciones de repositorios para PostgreSQL.
│               ├───[role_repository.go](pkg/infrastructure/persistence/postgres/role_repository.go) // Repositorio de roles para PostgreSQL.
│               └───[user_repository.go](pkg/infrastructure/persistence/postgres/user_repository.go) // Repositorio de usuarios para PostgreSQL.
└───static/                      // Contiene archivos estáticos (e.g., plantillas HTML para correos).
```

