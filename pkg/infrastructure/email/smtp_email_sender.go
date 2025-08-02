package email

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"

	"auth-microservice-go.v2/pkg/application/ports"
	"auth-microservice-go.v2/pkg/domain/entities"
)

// SMTPConfig configuración para SMTP
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// SMTPEmailSender implementa EmailSender usando SMTP
type SMTPEmailSender struct {
	config       SMTPConfig
	templates    map[string]*template.Template
	resetURL     string
	verifyURL    string
	siteName     string
	siteURL      string
	supportEmail string
}

// NewSMTPEmailSender crea una nueva instancia del enviador SMTP
func NewSMTPEmailSender(config SMTPConfig, resetURL, verifyURL, siteName, siteURL, supportEmail string) *SMTPEmailSender {
	templates := make(map[string]*template.Template)

	// Template para verificación de email
	templates["verification"] = template.Must(template.New("verification").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Verificación de Email</title>
			<style>
				body { 
					font-family: Arial, sans-serif;
					line-height: 1.6;
					color: #333;
					max-width: 600px;
					margin: 0 auto;
					padding: 20px;
				}
				.header {
					background-color: #4CAF50;
					color: white;
					padding: 20px;
					text-align: center;
					border-radius: 5px 5px 0 0;
				}
				.content {
					background-color: #fff;
					padding: 20px;
					border: 1px solid #ddd;
					border-radius: 0 0 5px 5px;
				}
				.button {
					display: inline-block;
					padding: 10px 20px;
					background-color: #4CAF50;
					color: white;
					text-decoration: none;
					border-radius: 5px;
					margin: 20px 0;
				}
				.footer {
					text-align: center;
					margin-top: 20px;
					font-size: 12px;
					color: #666;
				}
			</style>
		</head>
		<body>
			<div class="header">
				<h2>Verificación de Email</h2>
			</div>
			<div class="content">
				<p>Hola {{.UserFirstName}},</p>
				<p>Gracias por registrarte en {{.SiteName}}. Para completar tu registro, por favor verifica tu dirección de email:</p>
				<p style="text-align: center;">
					<a href="{{.VerifyURL}}?token={{.Token}}" class="button">Verificar Email</a>
				</p>
				<p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
				<p style="background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
					{{.VerifyURL}}?token={{.Token}}
				</p>
				<p><strong>Nota:</strong> Este enlace expirará en 24 horas por razones de seguridad.</p>
				<p>Si no has solicitado esta verificación, puedes ignorar este email.</p>
			</div>
			<div class="footer">
				<p>Este es un email automático, por favor no respondas a este mensaje.</p>
				<p>{{.SiteName}} - <a href="{{.SiteURL}}">{{.SiteURL}}</a></p>
				<p>¿Necesitas ayuda? Contacta a nuestro soporte: {{.SupportEmail}}</p>
			</div>
		</body>
		</html>
	`))

	// Template para reseteo de contraseña
	templates["password_reset"] = template.Must(template.New("password_reset").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Reseteo de Contraseña</title>
			<style>
				body { 
					font-family: Arial, sans-serif;
					line-height: 1.6;
					color: #333;
					max-width: 600px;
					margin: 0 auto;
					padding: 20px;
				}
				.header {
					background-color: #FF6B6B;
					color: white;
					padding: 20px;
					text-align: center;
					border-radius: 5px 5px 0 0;
				}
				.content {
					background-color: #fff;
					padding: 20px;
					border: 1px solid #ddd;
					border-radius: 0 0 5px 5px;
				}
				.button {
					display: inline-block;
					padding: 10px 20px;
					background-color: #FF6B6B;
					color: white;
					text-decoration: none;
					border-radius: 5px;
					margin: 20px 0;
				}
			</style>
		</head>
		<body>
			<div class="header">
				<h2>Reseteo de Contraseña</h2>
			</div>
			<div class="content">
				<p>Hola {{.UserFirstName}},</p>
				<p>Has solicitado resetear tu contraseña en {{.SiteName}}. Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
				<p style="text-align: center;">
					<a href="{{.ResetURL}}?token={{.Token}}" class="button">Resetear Contraseña</a>
				</p>
				<p>Si no puedes hacer clic en el enlace, copia y pega esta URL en tu navegador:</p>
				<p style="background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
					{{.ResetURL}}?token={{.Token}}
				</p>
				<p><strong>Importante:</strong> Este enlace expirará en 1 hora por seguridad.</p>
				<p>Si no has solicitado este reseteo de contraseña, puedes ignorar este email de manera segura.</p>
			</div>
		</body>
		</html>
	`))

	return &SMTPEmailSender{
		config:       config,
		templates:    templates,
		resetURL:     resetURL,
		verifyURL:    verifyURL,
		siteName:     siteName,
		siteURL:      siteURL,
		supportEmail: supportEmail,
	}
}

// SendVerificationEmail envía email de verificación
func (s *SMTPEmailSender) SendVerificationEmail(user *entities.User, token string) error {
	data := ports.EmailData{
		UserFirstName: user.Nombres,
		UserLastName:  user.ApellidoPaterno + " " + user.ApellidoMaterno,
		UserEmail:     user.Email,
		Token:         token,
		VerifyURL:     s.verifyURL,
		SiteName:      s.siteName,
		SiteURL:       s.siteURL,
		SupportEmail:  s.supportEmail,
	}

	return s.sendEmail(user.Email, "Verifica tu dirección de email", "verification", data)
}

// SendPasswordResetEmail envía email de reseteo de contraseña
func (s *SMTPEmailSender) SendPasswordResetEmail(user *entities.User, token string) error {
	data := ports.EmailData{
		UserFirstName: user.Nombres,
		UserLastName:  user.ApellidoPaterno + " " + user.ApellidoMaterno,
		UserEmail:     user.Email,
		Token:         token,
		ResetURL:      s.resetURL,
		SiteName:      s.siteName,
		SiteURL:       s.siteURL,
		SupportEmail:  s.supportEmail,
	}

	return s.sendEmail(user.Email, "Reseteo de contraseña", "password_reset", data)
}

// SendWelcomeEmail envía email de bienvenida
func (s *SMTPEmailSender) SendWelcomeEmail(user *entities.User) error {
	// TODO: Implementar template de bienvenida
	return nil
}

// SendPasswordChangedEmail notifica cambio de contraseña
func (s *SMTPEmailSender) SendPasswordChangedEmail(user *entities.User) error {
	// TODO: Implementar template de notificación
	return nil
}

// SendLoginNotificationEmail notifica nuevo inicio de sesión
func (s *SMTPEmailSender) SendLoginNotificationEmail(user *entities.User, ipAddress, userAgent string) error {
	// TODO: Implementar template de notificación de login
	return nil
}

// sendEmail método privado para enviar emails
func (s *SMTPEmailSender) sendEmail(to, subject, templateName string, data ports.EmailData) error {
	var body bytes.Buffer

	// Ejecutar template
	if err := s.templates[templateName].Execute(&body, data); err != nil {
		return fmt.Errorf("error ejecutando template: %v", err)
	}

	// Asegurar que el formato del campo From sea correcto
	// El formato debe ser: "Nombre <email@dominio.com>"
	// Si ya tiene los símbolos <>, no los agregamos de nuevo
	fromField := s.config.From
	if !strings.Contains(fromField, "<") && !strings.Contains(fromField, ">") {
		// Extraer el nombre y el email
		parts := strings.Split(fromField, " ")
		if len(parts) > 1 {
			// Si tiene formato "Nombre email@dominio.com", convertirlo a "Nombre <email@dominio.com>"
			email := parts[len(parts)-1]
			name := strings.Join(parts[:len(parts)-1], " ")
			fromField = fmt.Sprintf("%s <%s>", name, email)
		} else {
			// Si solo es el email, ponerlo entre <>
			fromField = fmt.Sprintf("<%s>", fromField)
		}
	}

	// Asegurar que el campo To tenga el formato correcto
	toField := to
	if !strings.Contains(toField, "<") && !strings.Contains(toField, ">") {
		toField = fmt.Sprintf("<%s>", toField)
	}

	// Construir mensaje con headers
	message := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"X-Priority: 1\r\n"+
			"X-Mailer: Auth Microservice\r\n"+
			"\r\n"+
			"%s",
		fromField,
		toField,
		subject,
		body.String()))

	// Configurar autenticación SMTP
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Enviar email
	err := smtp.SendMail(addr, auth, s.config.Username, []string{to}, message)
	if err != nil {
		return fmt.Errorf("error enviando email: %v", err)
	}

	return nil
}