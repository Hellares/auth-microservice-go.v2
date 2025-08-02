// pkg/application/ports/email_sender.go
package ports

import "auth-microservice-go.v2/pkg/domain/entities"

// EmailSender define la interfaz para enviar emails
type EmailSender interface {
	// SendVerificationEmail envía un email con un enlace de verificación
	SendVerificationEmail(user *entities.User, token string) error
	
	// SendPasswordResetEmail envía un email con un enlace para restablecer la contraseña
	SendPasswordResetEmail(user *entities.User, token string) error
	
	// SendWelcomeEmail envía un email de bienvenida al usuario
	SendWelcomeEmail(user *entities.User) error
	
	// SendPasswordChangedEmail notifica al usuario que su contraseña ha sido cambiada
	SendPasswordChangedEmail(user *entities.User) error
	
	// SendLoginNotificationEmail notifica al usuario sobre un nuevo inicio de sesión
	SendLoginNotificationEmail(user *entities.User, ipAddress, userAgent string) error
}

// EmailTemplate contiene la información para un email
type EmailTemplate struct {
	Subject string
	Body    string
}

// EmailData contiene los datos dinámicos para rellenar una plantilla de email
type EmailData struct {
	UserFirstName string
	UserLastName  string
	UserEmail     string
	Token         string
	VerifyURL     string
	ResetURL      string
	LoginIP       string
	LoginDate     string
	LoginBrowser  string
	SiteName      string
	SiteURL       string
	SupportEmail  string
}