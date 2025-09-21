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
	consumers    map[string]bool           // ✅ NUEVO: tracking de consumers activos
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
func NewRabbitMQEventBus(url, exchangeName, queueName string) (*RabbitMQEventBus, error) {
	log.Printf("🔧 NewRabbitMQEventBus iniciado: url=%s, exchange=%s, queue=%s", url, exchangeName, queueName)
	
	config := ConnectionConfig{
		URL:          url,
		ExchangeName: exchangeName,
		QueueName:    queueName,
		Durable:      true,
		AutoDelete:   false,
		Exclusive:    false,
		NoWait:       false,
	}

	log.Println("🔧 Config creado, creando EventBus...")
	
	eventBus := &RabbitMQEventBus{
		config:      config,
		subscribers: make(map[string]MessageHandler),
		consumers:   make(map[string]bool), // ✅ NUEVO: inicializar tracking
		done:        make(chan bool),
	}

	log.Println("🔧 EventBus struct creado, llamando connect()...")
	
	// Establecer conexión inicial
	if err := eventBus.connect(); err != nil {
		return nil, fmt.Errorf("error al conectar a RabbitMQ: %v", err)
	}

	log.Println("🔧 connect() exitoso, iniciando goroutine...")
	
	// Iniciar goroutine para monitorear reconexiones
	go eventBus.handleReconnection()

	log.Printf("✅ RabbitMQ EventBus inicializado correctamente")
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

	// Configurar confirmaciones de publicación
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
		eb.config.ExchangeName,
		"topic",
		eb.config.Durable,
		eb.config.AutoDelete,
		false,
		eb.config.NoWait,
		nil,
	)
	if err != nil {
		eb.channel.Close()
		eb.conn.Close()
		return fmt.Errorf("error al declarar exchange: %v", err)
	}

	// Declarar queue
	_, err = eb.channel.QueueDeclare(
		eb.config.QueueName,
		eb.config.Durable,
		eb.config.AutoDelete,
		eb.config.Exclusive,
		eb.config.NoWait,
		nil,
	)
	if err != nil {
		eb.channel.Close()
		eb.conn.Close()
		return fmt.Errorf("error al declarar queue: %v", err)
	}

	eb.reconnecting = false
	log.Printf("Conexión a RabbitMQ establecida exitosamente")

	// ✅ SOLO resubscribir si es una reconexión (no en conexión inicial)
	if len(eb.subscribers) > 0 {
		log.Println("🔧 Reconexión detectada, resubscribiendo...")
		eb.resubscribeAllInternal()
	}

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
	
	// ✅ LIMPIAR CONSUMERS AL RECONECTAR
	eb.consumers = make(map[string]bool)
	eb.mutex.Unlock()

	// Backoff exponencial
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

// resubscribeAllInternal reconfigura todas las suscripciones (solo interno)
func (eb *RabbitMQEventBus) resubscribeAllInternal() {
	// No usar mutex aquí porque ya está locked en connect()
	for routingKey, handler := range eb.subscribers {
		if err := eb.subscribeInternalNoLock(routingKey, handler); err != nil {
			log.Printf("Error al resuscribirse a %s: %v", routingKey, err)
		}
	}
}

// ============================================================================
// PUBLICACIÓN DE EVENTOS
// ============================================================================

// Publish publica un evento en RabbitMQ
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

	// Preparar mensaje
	message := amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
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
		if err := eb.channel.PublishWithContext(
			ctx,
			eb.config.ExchangeName,
			routingKey,
			false,
			false,
			message,
		); err != nil {
			return fmt.Errorf("error al publicar mensaje: %v", err)
		}
	}

	// Esperar confirmación de publicación
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

func (eb *RabbitMQEventBus) Subscribe(routingKey string, handler func([]byte) error) error {
    if eb.closed {
        return errors.New("EventBus está cerrado")
    }

    eb.mutex.Lock()
    defer eb.mutex.Unlock()

    // Verificar si ya existe un consumer para esta routing key
    if eb.consumers[routingKey] {
        log.Printf("Consumer ya existe para %s, omitiendo duplicado", routingKey)
        return nil
    }

    eb.subscribers[routingKey] = MessageHandler(handler)

    // Solo crear UN consumer para todo el queue la primera vez
    if len(eb.consumers) == 0 {
        if err := eb.createSingleConsumer(); err != nil {
            delete(eb.subscribers, routingKey)
            return err
        }
    }

    eb.consumers[routingKey] = true
    log.Printf("Handler registrado para routing key: %s", routingKey)
    
    return nil
}
// Crear un solo consumer que maneje todos los routing keys
func (eb *RabbitMQEventBus) createSingleConsumer() error {
    if eb.channel == nil {
        return errors.New("canal no disponible")
    }

    // No hacer bind - usar el queue directo
    msgs, err := eb.channel.Consume(
        eb.config.QueueName,
        fmt.Sprintf("consumer-%d", time.Now().UnixNano()),
        false,
        false,
        false,
        false,
        nil,
    )
    if err != nil {
        return fmt.Errorf("error al configurar consumidor: %v", err)
    }

    // Procesar mensajes con routing interno
    go eb.processAllMessages(msgs)

    log.Printf("Consumer único creado para queue: %s", eb.config.QueueName)
    return nil
}

// Procesar todos los mensajes y enrutar internamente

func (eb *RabbitMQEventBus) processAllMessages(msgs <-chan amqp.Delivery) {
    for msg := range msgs {
        if eb.closed {
            return
        }

        log.Printf("🔍 MENSAJE COMPLETO RECIBIDO:")
        log.Printf("   Exchange: %s", msg.Exchange)
        log.Printf("   Routing Key: %s", msg.RoutingKey)
        log.Printf("   Consumer Tag: %s", msg.ConsumerTag)
        log.Printf("   Headers: %+v", msg.Headers)
        log.Printf("   Body completo: %s", string(msg.Body))

        // Determinar el routing key del mensaje
        routingKey := eb.determineRoutingKey(msg.Body)
        
        log.Printf("✅ Routing Key determinado: %s", routingKey)

        // Buscar el handler apropiado
        eb.mutex.RLock()
        handler, exists := eb.subscribers[routingKey]
        eb.mutex.RUnlock()

        if !exists {
            log.Printf("❌ No hay handler para routing key: %s", routingKey)
            log.Printf("   Handlers disponibles: %v", eb.getAvailableHandlers())
            msg.Reject(false)
            continue
        }

        log.Printf("✅ Handler encontrado para: %s", routingKey)
        // Procesar mensaje
        eb.processMessage(msg, handler, routingKey)
    }
}

// Helper para debug
func (eb *RabbitMQEventBus) getAvailableHandlers() []string {
    eb.mutex.RLock()
    defer eb.mutex.RUnlock()
    
    var handlers []string
    for key := range eb.subscribers {
        handlers = append(handlers, key)
    }
    return handlers
}

// Determinar routing key basado en el contenido del mensaje

func (eb *RabbitMQEventBus) determineRoutingKey(body []byte) string {
    var eventData map[string]interface{}
    if err := json.Unmarshal(body, &eventData); err != nil {
        log.Printf("Error parseando JSON para determinar routing: %v", err)
        return "unknown"
    }

    // ✅ PRIMERO: Verificar si es un mensaje wrapeado de NestJS
    if pattern, hasPattern := eventData["pattern"].(string); hasPattern {
        log.Printf("🔍 Mensaje wrapeado detectado con pattern: %s", pattern)
        return pattern
    }

    // ✅ FALLBACK: Buscar indicadores en el JSON directo
    if _, hasID := eventData["id"]; hasID {
        if _, hasRUC := eventData["ruc"]; hasRUC {
            if _, hasCreadorID := eventData["creadorId"]; hasCreadorID {
                return "empresa.created"
            }
        }
        if _, hasEmpresaID := eventData["empresaId"]; hasEmpresaID {
            if _, hasRolID := eventData["rolId"]; hasRolID {
                return "usuario.created"
            } else {
                return "cliente.created"
            }
        }
    }

    log.Printf("🔍 No se pudo determinar routing key del mensaje: %s", string(body)[:200])
    return "unknown"
}

// Procesar un mensaje individual
func (eb *RabbitMQEventBus) processMessage(msg amqp.Delivery, handler MessageHandler, routingKey string) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Pánico procesando mensaje %s: %v", routingKey, r)
            msg.Nack(false, true)
        }
    }()

    done := make(chan error, 1)
    go func() {
        done <- handler(msg.Body)
    }()

    select {
    case err := <-done:
        if err != nil {
            log.Printf("Error procesando mensaje %s: %v", routingKey, err)
            if msg.Redelivered {
                msg.Reject(false)
                log.Printf("Mensaje rechazado definitivamente: %s", routingKey)
            } else {
                msg.Nack(false, true)
                log.Printf("Mensaje reenviado: %s", routingKey)
            }
        } else {
            msg.Ack(false)
            log.Printf("Mensaje procesado exitosamente: %s", routingKey)
        }
    case <-time.After(30 * time.Second):
        log.Printf("Timeout procesando mensaje %s", routingKey)
        msg.Nack(false, true)
    }
}

// subscribeInternalNoLock implementa la lógica interna de suscripción (sin mutex)
func (eb *RabbitMQEventBus) subscribeInternalNoLock(routingKey string, handler MessageHandler) error {
    if eb.channel == nil {
        return errors.New("canal no disponible")
    }

    // ✅ CREAR QUEUE ESPECÍFICO POR ROUTING KEY
    specificQueueName := fmt.Sprintf("%s.%s", eb.config.QueueName, routingKey)
    
    log.Printf("🔧 Creando queue específico: %s para routing key: %s", specificQueueName, routingKey)
    
    // Declarar queue específico
    _, err := eb.channel.QueueDeclare(
        specificQueueName,
        eb.config.Durable,
        eb.config.AutoDelete,
        eb.config.Exclusive,
        eb.config.NoWait,
        nil,
    )
    if err != nil {
        return fmt.Errorf("error al declarar queue %s: %v", specificQueueName, err)
    }

    // ✅ ENLAZAR QUEUE ESPECÍFICO AL EXCHANGE
    err = eb.channel.QueueBind(
        specificQueueName,      // queue específico
        routingKey,             // routing key
        eb.config.ExchangeName, // exchange
        false,
        nil,
    )
    if err != nil {
        return fmt.Errorf("error al enlazar queue %s: %v", specificQueueName, err)
    }

    // ✅ CONSUMIR DEL QUEUE ESPECÍFICO
    msgs, err := eb.channel.Consume(
        specificQueueName, // ✅ USAR QUEUE ESPECÍFICO
        fmt.Sprintf("consumer-%s-%d", routingKey, time.Now().UnixNano()),
        false,
        false,
        false,
        false,
        nil,
    )
    if err != nil {
        return fmt.Errorf("error al configurar consumidor: %v", err)
    }

    go eb.processMessages(routingKey, msgs, handler)
    log.Printf("Suscrito exitosamente a eventos: %s en queue: %s", routingKey, specificQueueName)
    return nil
}

// processMessages procesa los mensajes de una suscripción específica
func (eb *RabbitMQEventBus) processMessages(routingKey string, msgs <-chan amqp.Delivery, handler MessageHandler) {
	for msg := range msgs {
		if eb.closed {
			return
		}

		// ✅ DEBUG COMPLETO
        log.Printf("🔍 PROCESANDO MENSAJE:")
        log.Printf("   Expected Routing Key: %s", routingKey)
        log.Printf("   Actual Routing Key: %s", msg.RoutingKey) 
        log.Printf("   Exchange: %s", msg.Exchange)
        log.Printf("   Consumer Tag: %s", msg.ConsumerTag)
        log.Printf("   Headers: %+v", msg.Headers)
        log.Printf("   Body (first 200 chars): %.200s", string(msg.Body))
        log.Printf("   Redelivered: %t", msg.Redelivered)

		// Procesar mensaje con recuperación de pánico
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Pánico procesando mensaje %s: %v", routingKey, r)
					msg.Nack(false, true)
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

					if msg.Redelivered {
						msg.Reject(false)
						log.Printf("Mensaje rechazado definitivamente: %s", routingKey)
					} else {
						msg.Nack(false, true)
						log.Printf("Mensaje reenviado: %s", routingKey)
					}
				} else {
					msg.Ack(false)
					log.Printf("Mensaje procesado exitosamente: %s", routingKey)
				}
			case <-time.After(30 * time.Second):
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

	_, err := eb.channel.QueueInspect(eb.config.QueueName)
	if err != nil {
		return fmt.Errorf("error en health check: %v", err)
	}

	return nil
}