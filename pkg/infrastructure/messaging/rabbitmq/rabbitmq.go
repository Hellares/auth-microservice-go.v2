// // pkg/infrastructure/messaging/rabbitmq/rabbitmq.go
// package rabbitmq

// import (
// 	"context"
// 	"encoding/json"
// 	"log"
// 	"time"

// 	amqp "github.com/rabbitmq/amqp091-go"
// )

// // EventBus representa la interfaz para publicar y consumir eventos
// type EventBus interface {
// 	Publish(ctx context.Context, routingKey string, event interface{}) error
// 	Subscribe(routingKey string, handler func([]byte) error) error
// 	Close() error
// }

// // RabbitMQEventBus implementa EventBus con RabbitMQ
// type RabbitMQEventBus struct {
// 	conn         *amqp.Connection
// 	channel      *amqp.Channel
// 	exchangeName string
// 	queueName    string
// }

// // NewRabbitMQEventBus crea una nueva instancia de RabbitMQEventBus
// func NewRabbitMQEventBus(url, exchangeName, queueName string) (*RabbitMQEventBus, error) {
// 	// Conectar a RabbitMQ
// 	conn, err := amqp.Dial(url)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Crear canal
// 	channel, err := conn.Channel()
// 	if err != nil {
// 		conn.Close()
// 		return nil, err
// 	}

// 	// Declarar exchange
// 	err = channel.ExchangeDeclare(
// 		exchangeName, // nombre
// 		"topic",      // tipo
// 		true,         // durable
// 		false,        // auto-delete
// 		false,        // internal
// 		false,        // no-wait
// 		nil,          // arguments
// 	)
// 	if err != nil {
// 		channel.Close()
// 		conn.Close()
// 		return nil, err
// 	}

// 	// Declarar cola
// 	_, err = channel.QueueDeclare(
// 		queueName, // nombre
// 		true,      // durable
// 		false,     // delete when unused
// 		false,     // exclusive
// 		false,     // no-wait
// 		nil,       // arguments
// 	)
// 	if err != nil {
// 		channel.Close()
// 		conn.Close()
// 		return nil, err
// 	}

// 	return &RabbitMQEventBus{
// 		conn:         conn,
// 		channel:      channel,
// 		exchangeName: exchangeName,
// 		queueName:    queueName,
// 	}, nil
// }

// // Publish publica un evento en RabbitMQ
// func (eb *RabbitMQEventBus) Publish(ctx context.Context, routingKey string, event interface{}) error {
// 	// Convertir evento a JSON
// 	body, err := json.Marshal(event)
// 	if err != nil {
// 		return err
// 	}

// 	// Publicar mensaje
// 	return eb.channel.PublishWithContext(
// 		ctx,
// 		eb.exchangeName, // exchange
// 		routingKey,      // routing key
// 		false,           // mandatory
// 		false,           // immediate
// 		amqp.Publishing{
// 			ContentType:  "application/json",
// 			DeliveryMode: amqp.Persistent,
// 			Timestamp:    time.Now(),
// 			Body:         body,
// 		},
// 	)
// }

// // Subscribe se suscribe a eventos con una clave de enrutamiento específica
// func (eb *RabbitMQEventBus) Subscribe(routingKey string, handler func([]byte) error) error {
// 	// Enlazar cola a exchange con routing key
// 	err := eb.channel.QueueBind(
// 		eb.queueName,    // queue name
// 		routingKey,      // routing key
// 		eb.exchangeName, // exchange
// 		false,
// 		nil,
// 	)
// 	if err != nil {
// 		return err
// 	}

// 	// Consumir mensajes
// 	msgs, err := eb.channel.Consume(
// 		eb.queueName, // queue
// 		"",           // consumer
// 		false,        // auto-ack
// 		false,        // exclusive
// 		false,        // no-local
// 		false,        // no-wait
// 		nil,          // args
// 	)
// 	if err != nil {
// 		return err
// 	}

// 	// Procesar mensajes en goroutine
// 	go func() {
// 		for msg := range msgs {
// 			err := handler(msg.Body)
// 			if err != nil {
// 				log.Printf("Error procesando mensaje: %v", err)
// 				// Rechazar mensaje para que sea re-encolado
// 				msg.Nack(false, true)
// 			} else {
// 				// Confirmar mensaje
// 				msg.Ack(false)
// 			}
// 		}
// 	}()

// 	return nil
// }

// // Close cierra la conexión a RabbitMQ
// func (eb *RabbitMQEventBus) Close() error {
// 	if err := eb.channel.Close(); err != nil {
// 		return err
// 	}
// 	return eb.conn.Close()
// }

// pkg/infrastructure/messaging/rabbitmq/rabbitmq.go
package rabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ============================================================================
// INTERFACES Y TIPOS PÚBLICOS
// ============================================================================

// EventBus interfaz principal para publicar y consumir eventos
// Define el contrato que debe cumplir cualquier implementación de message broker
type EventBus interface {
	Publish(ctx context.Context, routingKey string, event interface{}) error
	Subscribe(routingKey string, handler func([]byte) error) error
	Close() error
	IsConnected() bool
}

// MessageHandler función que procesa mensajes recibidos
type MessageHandler func([]byte) error

// ConnectionConfig configuración para la conexión a RabbitMQ
type ConnectionConfig struct {
	URL          string
	ExchangeName string
	QueueName    string
	Durable      bool
	AutoDelete   bool
	Exclusive    bool
	NoWait       bool
}

// ============================================================================
// IMPLEMENTACIÓN PRINCIPAL
// ============================================================================

// RabbitMQEventBus implementa EventBus usando RabbitMQ
type RabbitMQEventBus struct {
	config       ConnectionConfig
	conn         *amqp.Connection
	channel      *amqp.Channel
	closed       bool
	reconnecting bool
	subscribers  map[string]MessageHandler // routingKey -> handler
	mutex        sync.RWMutex

	// Canales para manejo de reconexión
	notifyClose   chan *amqp.Error
	notifyConfirm chan amqp.Confirmation
	done          chan bool
}

// ============================================================================
// CONSTRUCTOR Y CONFIGURACIÓN
// ============================================================================

// NewRabbitMQEventBus crea una nueva instancia del EventBus
// Establece la conexión inicial y configura el exchange y queue
func NewRabbitMQEventBus(url, exchangeName, queueName string) (*RabbitMQEventBus, error) {
	config := ConnectionConfig{
		URL:          url,
		ExchangeName: exchangeName,
		QueueName:    queueName,
		Durable:      true,  // Sobrevive a reinicios del servidor
		AutoDelete:   false, // No se elimina automáticamente
		Exclusive:    false, // Puede ser usada por múltiples consumidores
		NoWait:       false, // Esperar confirmación del servidor
	}

	eventBus := &RabbitMQEventBus{
		config:      config,
		subscribers: make(map[string]MessageHandler),
		done:        make(chan bool),
	}

	// Establecer conexión inicial
	if err := eventBus.connect(); err != nil {
		return nil, fmt.Errorf("error al conectar a RabbitMQ: %v", err)
	}

	// Iniciar goroutine para monitorear reconexiones
	go eventBus.handleReconnection()

	log.Printf("RabbitMQ EventBus inicializado correctamente")
	return eventBus, nil
}

// ============================================================================
// GESTIÓN DE CONEXIÓN Y RECONEXIÓN
// ============================================================================

// connect establece la conexión a RabbitMQ y configura el canal
func (eb *RabbitMQEventBus) connect() error {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	if eb.closed {
		return errors.New("EventBus está cerrado")
	}

	var err error

	// Establecer conexión
	eb.conn, err = amqp.Dial(eb.config.URL)
	if err != nil {
		return fmt.Errorf("error al conectar a RabbitMQ: %v", err)
	}

	// Crear canal
	eb.channel, err = eb.conn.Channel()
	if err != nil {
		eb.conn.Close()
		return fmt.Errorf("error al crear canal: %v", err)
	}

	// Configurar confirmaciones de publicación (importante para reliability)
	if err := eb.channel.Confirm(false); err != nil {
		eb.channel.Close()
		eb.conn.Close()
		return fmt.Errorf("error al configurar confirmaciones: %v", err)
	}

	// Configurar notificaciones
	eb.notifyClose = make(chan *amqp.Error, 1)
	eb.notifyConfirm = make(chan amqp.Confirmation, 1)

	eb.channel.NotifyClose(eb.notifyClose)
	eb.channel.NotifyPublish(eb.notifyConfirm)

	// Declarar exchange
	err = eb.channel.ExchangeDeclare(
		eb.config.ExchangeName, // nombre
		"topic",                // tipo: topic permite routing patterns flexibles
		eb.config.Durable,      // durable: sobrevive a reinicios
		eb.config.AutoDelete,   // auto-delete: no se elimina automáticamente
		false,                  // internal: puede recibir mensajes externos
		eb.config.NoWait,       // no-wait: esperar confirmación
		nil,                    // arguments: sin argumentos adicionales
	)
	if err != nil {
		eb.channel.Close()
		eb.conn.Close()
		return fmt.Errorf("error al declarar exchange: %v", err)
	}

	// Declarar queue
	_, err = eb.channel.QueueDeclare(
		eb.config.QueueName,  // nombre
		eb.config.Durable,    // durable
		eb.config.AutoDelete, // auto-delete
		eb.config.Exclusive,  // exclusive
		eb.config.NoWait,     // no-wait
		nil,                  // arguments
	)
	if err != nil {
		eb.channel.Close()
		eb.conn.Close()
		return fmt.Errorf("error al declarar queue: %v", err)
	}

	eb.reconnecting = false
	log.Printf("Conexión a RabbitMQ establecida exitosamente")

	// Reconfigurar suscripciones después de reconectar
	eb.resubscribeAll()

	return nil
}

// handleReconnection maneja las reconexiones automáticas
func (eb *RabbitMQEventBus) handleReconnection() {
	for {
		select {
		case err := <-eb.notifyClose:
			if err != nil {
				log.Printf("Conexión a RabbitMQ perdida: %v", err)
				eb.reconnect()
			}
		case <-eb.done:
			return
		}
	}
}

// reconnect intenta reconectar con backoff exponencial
func (eb *RabbitMQEventBus) reconnect() {
	eb.mutex.Lock()
	if eb.closed || eb.reconnecting {
		eb.mutex.Unlock()
		return
	}
	eb.reconnecting = true
	eb.mutex.Unlock()

	// Backoff exponencial: 1s, 2s, 4s, 8s, máx 30s
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		if eb.closed {
			return
		}

		log.Printf("Intentando reconectar a RabbitMQ en %v...", backoff)
		time.Sleep(backoff)

		if err := eb.connect(); err != nil {
			log.Printf("Error en reconexión: %v", err)

			// Aumentar backoff exponencialmente
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("Reconexión exitosa a RabbitMQ")
		return
	}
}

// resubscribeAll reconfigura todas las suscripciones después de reconectar
func (eb *RabbitMQEventBus) resubscribeAll() {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	for routingKey, handler := range eb.subscribers {
		if err := eb.subscribeInternal(routingKey, handler); err != nil {
			log.Printf("Error al resuscribirse a %s: %v", routingKey, err)
		}
	}
}

// ============================================================================
// PUBLICACIÓN DE EVENTOS
// ============================================================================

// Publish publica un evento en RabbitMQ
// El evento se serializa a JSON y se envía con el routing key especificado
func (eb *RabbitMQEventBus) Publish(ctx context.Context, routingKey string, event interface{}) error {
	if eb.closed {
		return errors.New("EventBus está cerrado")
	}

	eb.mutex.RLock()
	if eb.reconnecting {
		eb.mutex.RUnlock()
		return errors.New("EventBus está reconectando, intente más tarde")
	}

	if eb.channel == nil {
		eb.mutex.RUnlock()
		return errors.New("canal no disponible")
	}
	eb.mutex.RUnlock()

	// Serializar evento a JSON
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("error al serializar evento: %v", err)
	}

	// Preparar mensaje con headers adicionales para trazabilidad
	message := amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent, // Persistir mensaje en disco
		Timestamp:    time.Now(),
		MessageId:    generateMessageID(),
		Body:         body,
		Headers: amqp.Table{
			"origin":     "auth-microservice",
			"event_type": routingKey,
			"version":    "1.0",
		},
	}

	// Publicar con timeout del contexto
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Publicar mensaje
		if err := eb.channel.PublishWithContext(
			ctx,
			eb.config.ExchangeName, // exchange
			routingKey,             // routing key
			false,                  // mandatory: no fallar si no hay consumidores
			false,                  // immediate: no fallar si no hay consumidores listos
			message,
		); err != nil {
			return fmt.Errorf("error al publicar mensaje: %v", err)
		}
	}

	// Esperar confirmación de publicación (importante para reliability)
	select {
	case confirm := <-eb.notifyConfirm:
		if confirm.Ack {
			log.Printf("Evento publicado exitosamente: %s", routingKey)
			return nil
		} else {
			return errors.New("mensaje no confirmado por RabbitMQ")
		}
	case <-time.After(5 * time.Second):
		return errors.New("timeout esperando confirmación de publicación")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ============================================================================
// SUSCRIPCIÓN A EVENTOS
// ============================================================================

// Subscribe se suscribe a eventos con una clave de enrutamiento específica
func (eb *RabbitMQEventBus) Subscribe(routingKey string, handler func([]byte) error) error {
	if eb.closed {
		return errors.New("EventBus está cerrado")
	}

	eb.mutex.Lock()
	eb.subscribers[routingKey] = MessageHandler(handler)
	eb.mutex.Unlock()

	return eb.subscribeInternal(routingKey, MessageHandler(handler))
}

// subscribeInternal implementa la lógica interna de suscripción
func (eb *RabbitMQEventBus) subscribeInternal(routingKey string, handler MessageHandler) error {
	if eb.channel == nil {
		return errors.New("canal no disponible")
	}

	// Enlazar queue al exchange con el routing key
	err := eb.channel.QueueBind(
		eb.config.QueueName,    // queue name
		routingKey,             // routing key
		eb.config.ExchangeName, // exchange
		false,                  // no-wait
		nil,                    // arguments
	)
	if err != nil {
		return fmt.Errorf("error al enlazar queue: %v", err)
	}

	// Configurar consumidor
	msgs, err := eb.channel.Consume(
		eb.config.QueueName, // queue
		"",                  // consumer tag (auto-generado)
		false,               // auto-ack: false para control manual
		false,               // exclusive
		false,               // no-local
		false,               // no-wait
		nil,                 // args
	)
	if err != nil {
		return fmt.Errorf("error al configurar consumidor: %v", err)
	}

	// Procesar mensajes en goroutine dedicada
	go eb.processMessages(routingKey, msgs, handler)

	log.Printf("Suscrito exitosamente a eventos: %s", routingKey)
	return nil
}

// processMessages procesa los mensajes de una suscripción específica
func (eb *RabbitMQEventBus) processMessages(routingKey string, msgs <-chan amqp.Delivery, handler MessageHandler) {
	for msg := range msgs {
		if eb.closed {
			return
		}

		// Procesar mensaje con recuperación de pánico
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Pánico procesando mensaje %s: %v", routingKey, r)
					msg.Nack(false, true) // Reenviar mensaje
				}
			}()

			// Ejecutar handler con timeout
			done := make(chan error, 1)
			go func() {
				done <- handler(msg.Body)
			}()

			select {
			case err := <-done:
				if err != nil {
					log.Printf("Error procesando mensaje %s: %v", routingKey, err)

					// Estrategia de reintento simple
					if msg.Redelivered {
						// Si ya fue reenviado, rechazar definitivamente
						msg.Reject(false)
						log.Printf("Mensaje rechazado definitivamente: %s", routingKey)
					} else {
						// Primer error: reenviar
						msg.Nack(false, true)
						log.Printf("Mensaje reenviado: %s", routingKey)
					}
				} else {
					// Éxito: confirmar mensaje
					msg.Ack(false)
					log.Printf("Mensaje procesado exitosamente: %s", routingKey)
				}
			case <-time.After(30 * time.Second):
				// Timeout procesando mensaje
				log.Printf("Timeout procesando mensaje %s", routingKey)
				msg.Nack(false, true)
			}
		}()
	}
}

// ============================================================================
// UTILIDADES Y GESTIÓN DE CICLO DE VIDA
// ============================================================================

// IsConnected verifica si la conexión está activa
func (eb *RabbitMQEventBus) IsConnected() bool {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	return eb.conn != nil && !eb.conn.IsClosed() && eb.channel != nil && !eb.reconnecting
}

// Close cierra la conexión y limpia recursos
func (eb *RabbitMQEventBus) Close() error {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	if eb.closed {
		return nil
	}

	eb.closed = true
	close(eb.done)

	var lastErr error

	// Cerrar canal
	if eb.channel != nil {
		if err := eb.channel.Close(); err != nil {
			lastErr = err
			log.Printf("Error cerrando canal: %v", err)
		}
	}

	// Cerrar conexión
	if eb.conn != nil {
		if err := eb.conn.Close(); err != nil {
			lastErr = err
			log.Printf("Error cerrando conexión: %v", err)
		}
	}

	log.Printf("RabbitMQ EventBus cerrado")
	return lastErr
}

// generateMessageID genera un ID único para el mensaje
func generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

// ============================================================================
// MÉTODO AUXILIAR PARA HEALTH CHECKS
// ============================================================================

// HealthCheck verifica el estado de la conexión
func (eb *RabbitMQEventBus) HealthCheck() error {
	if !eb.IsConnected() {
		return errors.New("no conectado a RabbitMQ")
	}

	// Intentar una operación simple para verificar conectividad
	_, err := eb.channel.QueueInspect(eb.config.QueueName)
	if err != nil {
		return fmt.Errorf("error en health check: %v", err)
	}

	return nil
}
