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
	"auth-microservice-go.v2/pkg/infrastructure/persistence/postgres"
)

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
	viper.SetDefault("database.max_open_conns", 20)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")
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

	db.SetMaxOpenConns(viper.GetInt("database.max_open_conns"))
	db.SetMaxIdleConns(viper.GetInt("database.max_idle_conns"))
	db.SetConnMaxLifetime(viper.GetDuration("database.conn_max_lifetime"))

	log.Println("Conexión a base de datos establecida con éxito")
	return db, nil
}

// InitializeServices inicializa todos los servicios necesarios
// ✅ FIRMA CORREGIDA: incluye db.DB como tercer parámetro
func InitializeServices(db *sqlx.DB, emailSender ports.EmailSender, sqlDB *sql.DB) services.AuthService {
	// Inicializar repositorios
	userRepo := postgres.NewUserRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	permissionRepo := postgres.NewPermissionRepository(db)
	userEmpresaRoleRepo := postgres.NewUserEmpresaRoleRepository(db)
	verificationTokenRepo := postgres.NewVerificationTokenRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	systemRoleRepo := postgres.NewSystemRoleRepository(db)

	// Inicializar servicios
	jwtSecret := viper.GetString("auth.jwt_secret")
	tokenExpiration := viper.GetDuration("auth.token_expiration")

	authService := services.NewAuthService(
		userRepo,
		roleRepo,
		permissionRepo,
		userEmpresaRoleRepo,
		verificationTokenRepo,
		sessionRepo,
		systemRoleRepo,
		jwtSecret,
		tokenExpiration,
		emailSender,
		sqlDB, // ✅ Pasar la conexión sql.DB también
	)

	return authService
}

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

	// Imprimir todas las rutas registradas (para debugging)
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err == nil {
			log.Printf("Ruta registrada: %s", pathTemplate)
		}
		return nil
	})

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}

// loggingMiddleware es un middleware para registrar todas las peticiones HTTP
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
	})
}