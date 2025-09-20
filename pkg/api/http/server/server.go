// pkg/api/http/server/server.go
package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"

	"auth-microservice-go.v2/pkg/api/http/handlers"
	"auth-microservice-go.v2/pkg/application/ports"
	"auth-microservice-go.v2/pkg/application/services"
	"auth-microservice-go.v2/pkg/domain/repositories"
	"auth-microservice-go.v2/pkg/infrastructure/persistence/postgres"
)

// ✅ NUEVO: Estructura para manejar repositorios con cleanup
type Repositories struct {
	UserRepo              repositories.UserRepository
	RoleRepo              repositories.RoleRepository
	PermissionRepo        repositories.PermissionRepository
	UserEmpresaRoleRepo   repositories.UserEmpresaRoleRepository
	VerificationTokenRepo repositories.VerificationTokenRepository
	SessionRepo           repositories.SessionRepository
	SystemRoleRepo        repositories.SystemRoleRepository
}

// ✅ NUEVO: Método para cerrar prepared statements
func (r *Repositories) Close() error {
	// Solo cerrar si el repo implementa Close()
	if closer, ok := r.UserEmpresaRoleRepo.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// LoadConfig carga la configuración desde archivos o variables de entorno
func LoadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Para leer variables de entorno
	viper.AutomaticEnv()
	viper.SetEnvPrefix("")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Valores por defecto
	viper.SetDefault("server.port", "3003")
	viper.SetDefault("server.env", "development")
	viper.SetDefault("database.max_open_conns", 50)
	viper.SetDefault("database.max_idle_conns", 25)
	viper.SetDefault("database.conn_max_lifetime", "10m")
	viper.SetDefault("database.conn_max_idle_time", "5m")
	viper.SetDefault("auth.token_expiration", "24h")

	// Intentar leer del archivo de configuración
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No se encontró archivo de configuración, usando variables de entorno")
		} else {
			return err
		}
	}

	// Validar configuración requerida
	requiredKeys := []string{
		"database.host",
		"database.port",
		"database.user",
		"database.password",
		"database.name",
		"auth.jwt_secret",
	}

	for _, key := range requiredKeys {
		if !viper.IsSet(key) {
			return fmt.Errorf("falta configuración requerida: %s", key)
		}
	}

	return nil
}

// ConnectDB establece la conexión a la base de datos
func ConnectDB() (*sqlx.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		viper.GetString("database.host"),
		viper.GetString("database.port"),
		viper.GetString("database.user"),
		viper.GetString("database.password"),
		viper.GetString("database.name"),
	)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// ✅ Configuración optimizada del pool de conexiones
	db.SetMaxOpenConns(viper.GetInt("database.max_open_conns"))
	db.SetMaxIdleConns(viper.GetInt("database.max_idle_conns"))
	db.SetConnMaxLifetime(viper.GetDuration("database.conn_max_lifetime"))

	// ✅ NUEVO: Configurar idle timeout
	if viper.IsSet("database.conn_max_idle_time") {
		db.SetConnMaxIdleTime(viper.GetDuration("database.conn_max_idle_time"))
	}

	// ✅ Verificar conexión
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error verificando conexión a la base de datos: %v", err)
	}

	log.Printf("Conexión a base de datos establecida con éxito - Pool: %d max, %d idle", 
		viper.GetInt("database.max_open_conns"),
		viper.GetInt("database.max_idle_conns"))
	return db, nil
}

// ✅ NUEVO: InitializeRepositories inicializa repositorios con manejo de errores
func InitializeRepositories(db *sqlx.DB) (*Repositories, error) {
	log.Println("Inicializando repositorios...")

	// Inicializar repositorio con prepared statements
	userEmpresaRoleRepo, err := postgres.NewUserEmpresaRoleRepository(db)
	if err != nil {
		return nil, fmt.Errorf("error inicializando UserEmpresaRoleRepository: %v", err)
	}

	repos := &Repositories{
		UserRepo:              postgres.NewUserRepository(db),
		RoleRepo:              postgres.NewRoleRepository(db),
		PermissionRepo:        postgres.NewPermissionRepository(db),
		UserEmpresaRoleRepo:   userEmpresaRoleRepo,
		VerificationTokenRepo: postgres.NewVerificationTokenRepository(db),
		SessionRepo:           postgres.NewSessionRepository(db),
		SystemRoleRepo:        postgres.NewSystemRoleRepository(db),
	}

	log.Println("Repositorios inicializados correctamente")
	return repos, nil
}
// InitializeServices inicializa todos los servicios necesarios
// ✅ FIRMA CORREGIDA: incluye db.DB como tercer parámetro
// func InitializeServices(db *sqlx.DB, emailSender ports.EmailSender, sqlDB *sql.DB) services.AuthService {
// 	log.Println("Inicializando servicios...")

	
// 	// Inicializar repositorios
// 	userRepo := postgres.NewUserRepository(db)
// 	roleRepo := postgres.NewRoleRepository(db)
// 	permissionRepo := postgres.NewPermissionRepository(db)
// 	userEmpresaRoleRepo := postgres.NewUserEmpresaRoleRepository(db)
// 	verificationTokenRepo := postgres.NewVerificationTokenRepository(db)
// 	sessionRepo := postgres.NewSessionRepository(db)
// 	systemRoleRepo := postgres.NewSystemRoleRepository(db)

// 	// Inicializar servicios
// 	jwtSecret := viper.GetString("auth.jwt_secret")
// 	tokenExpiration := viper.GetDuration("auth.token_expiration")

// 	authService := services.NewAuthService(
// 		userRepo,
// 		roleRepo,
// 		permissionRepo,
// 		userEmpresaRoleRepo,
// 		verificationTokenRepo,
// 		sessionRepo,
// 		systemRoleRepo,
// 		jwtSecret,
// 		tokenExpiration,
// 		emailSender,
// 		sqlDB, // ✅ Pasar la conexión sql.DB también
// 	)

// 	return authService
// }

// ✅ ACTUALIZADO: InitializeServices ahora recibe Repositories
func InitializeServices(repos *Repositories, emailSender ports.EmailSender, sqlDB *sql.DB) services.AuthService {
	log.Println("Inicializando servicios...")

	// Configuración JWT
	jwtSecret := viper.GetString("auth.jwt_secret")
	tokenExpiration := viper.GetDuration("auth.token_expiration")

	authService := services.NewAuthService(
		repos.UserRepo,
		repos.RoleRepo,
		repos.PermissionRepo,
		repos.UserEmpresaRoleRepo,
		repos.VerificationTokenRepo,
		repos.SessionRepo,
		repos.SystemRoleRepo,
		jwtSecret,
		tokenExpiration,
		emailSender,
		sqlDB,
	)

	log.Println("Servicios inicializados correctamente")
	return authService
}
// SetupRouter configura el router con todos los handlers
// func SetupRouter(authService services.AuthService) *mux.Router {
// 	// Inicializar router
// 	router := mux.NewRouter()
// 	router.Use(loggingMiddleware)

// 	// Servir archivos estáticos primero
// 	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

// 	// Ruta específica para email-verified.html en la raíz
// 	router.HandleFunc("/email-verified.html", func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 		http.ServeFile(w, r, "static/email-verified.html")
// 	}).Methods("GET")

// 	// Inicializar handlers
// 	authHandler := handlers.NewAuthHandler(authService)

// 	// Definir rutas
// 	apiRouter := router.PathPrefix("/api").Subrouter()
// 	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
// 	authHandler.RegisterRoutes(authRouter)

// 	// Imprimir todas las rutas registradas (para debugging)
// 	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
// 		pathTemplate, err := route.GetPathTemplate()
// 		if err == nil {
// 			log.Printf("Ruta registrada: %s", pathTemplate)
// 		}
// 		return nil
// 	})

// 	// Health check
// 	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte("OK"))
// 	}).Methods("GET")

// 	return router
// }

// SetupRouter configura el router con todos los handlers
func SetupRouter(authService services.AuthService) *mux.Router {
	// Inicializar router
	router := mux.NewRouter()
	router.Use(loggingMiddleware)

	// Servir archivos estáticos primero
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Ruta específica para email-verified.html en la raíz
	router.HandleFunc("/email-verified.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "static/email-verified.html")
	}).Methods("GET")

	// Inicializar handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Definir rutas
	apiRouter := router.PathPrefix("/api").Subrouter()
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()
	authHandler.RegisterRoutes(authRouter)

	// ✅ Imprimir rutas solo en desarrollo
	if viper.GetString("server.env") == "development" {
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			pathTemplate, err := route.GetPathTemplate()
			if err == nil {
				log.Printf("Ruta registrada: %s", pathTemplate)
			}
			return nil
		})
	}

	// Health check mejorado
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"auth-microservice"}`))
	}).Methods("GET")

	return router
}
// loggingMiddleware es un middleware para registrar todas las peticiones HTTP
// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		start := time.Now()
// 		next.ServeHTTP(w, r)
// 		log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
// 	})
// }

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrapper para capturar status code
		wrapped := &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		// Log detallado solo en desarrollo
		if viper.GetString("server.env") == "development" {
			log.Printf("%s %s %d %s %s", 
				r.Method, 
				r.RequestURI, 
				wrapped.statusCode,
				duration,
				r.UserAgent())
		} else {
			// Log básico en producción
			log.Printf("%s %s %d %s", r.Method, r.RequestURI, wrapped.statusCode, duration)
		}
	})
}

// ✅ NUEVO: Wrapper para capturar status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}