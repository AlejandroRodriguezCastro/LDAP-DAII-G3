import structlog
import json
from typing import Any, Dict
import aio_pika
import datetime
from app.config.rabbitmq_singleton import RabbitMQSingleton
from app.config.settings import settings

logger = structlog.get_logger()


class RabbitMQPort:
    """
    Outbound adapter for RabbitMQ message publishing.
    Implements the port pattern to maintain scalability and decoupling.
    """

    def __init__(self, rabbitmq_singleton: RabbitMQSingleton):
        """
        Initialize RabbitMQ port with singleton connection.

        Args:
            rabbitmq_singleton: RabbitMQ singleton instance for connection management
        """
        self.rabbitmq_singleton = rabbitmq_singleton
        logger.info("Initializing RabbitMQPort with singleton connection")

    async def publish_message(
        self,
        message_body: Dict[str, Any],
        routing_key: str = None,
        content_type: str = None,
        delivery_mode: int = None
    ) -> bool:
        """
        Publish a message to RabbitMQ exchange.

        Args:
            message_body: Dictionary containing the message payload
            routing_key: Optional custom routing key (defaults to settings)
            content_type: Optional custom content type (defaults to settings)
            delivery_mode: Optional custom delivery mode (defaults to settings)

        Returns:
            bool: True if message was published successfully, False otherwise

        Raises:
            Exception: If connection or publishing fails
        """
        try:
            routing_key = routing_key or settings.RABBITMQ_ROUTING_KEY
            content_type = content_type or settings.RABBITMQ_MESSAGE_CONTENT_TYPE
            delivery_mode = delivery_mode or settings.RABBITMQ_DELIVERY_MODE

            # Ensure connection is established
            await self.rabbitmq_singleton.connect()

            # Get exchange for publishing
            exchange = await self.rabbitmq_singleton.get_exchange()

            # Serialize message body to JSON
            message_body_json = json.dumps(message_body)

            # Create aio_pika message with specified properties
            message = aio_pika.Message(
                body=message_body_json.encode('utf-8'),
                content_type=content_type,
                delivery_mode=aio_pika.DeliveryMode(delivery_mode)
            )

            # Publish message
            await exchange.publish(message, routing_key=routing_key)

            logger.info(
                "Message published to RabbitMQ",
                exchange=settings.RABBITMQ_EXCHANGE,
                routing_key=routing_key,
                message_size=len(message_body_json)
            )
            return True

        except Exception as e:
            logger.exception(
                "Failed to publish message to RabbitMQ",
                routing_key=routing_key,
                error=str(e)
            )
            raise

    async def publish_log_message(
        self,
        log_level: str,
        message: str,
        source: str,
        **additional_context
    ) -> bool:
        """
        Convenience method to publish a structured log message.

        Args:
            log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Main log message
            source: Source of the log (e.g., 'LDAP_SERVICE', 'AUTH_HANDLER')
            **additional_context: Additional context fields to include in the message

        Returns:
            bool: True if message was published successfully
        """
        log_payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "log_level": log_level,
            "message": message,
            "source": source,
            **additional_context
        }

        return await self.publish_message(log_payload)

    async def publish_audit_log(
        self,
        action: str,
        user: str,
        resource: str,
        status: str,
        **additional_context
    ) -> bool:
        """
        Convenience method to publish audit log messages.

        Args:
            action: Action performed (e.g., 'CREATE_USER', 'DELETE_ORGANIZATION')
            user: User performing the action
            resource: Resource affected
            status: Status of the action (SUCCESS, FAILURE)
            **additional_context: Additional audit context

        Returns:
            bool: True if message was published successfully
        """
        audit_payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "action": action,
            "user": user,
            "resource": resource,
            "status": status,
            **additional_context
        }

        return await self.publish_message(audit_payload)
