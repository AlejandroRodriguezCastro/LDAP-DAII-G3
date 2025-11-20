import structlog
from app.config.rabbitmq_singleton import get_rabbitmq_instance
from app.ports.outbound.rabbitmq_port import RabbitMQPort

logger = structlog.get_logger()

# Module-level cache for singleton RabbitMQ service
_rabbitmq_port_instance: RabbitMQPort = None


async def get_rabbitmq_port_instance() -> RabbitMQPort:
    """
    Factory function to get or create the RabbitMQ port singleton instance.
    This ensures only one RabbitMQ port instance is used throughout the application.

    Returns:
        RabbitMQPort: The singleton RabbitMQ port instance

    Usage:
        from app.infra.rabbitmq_service_factory import get_rabbitmq_port_instance

        # In your handler or controller
        rabbitmq_port = await get_rabbitmq_port_instance()
        await rabbitmq_port.publish_log_message(
            log_level="INFO",
            message="User created successfully",
            source="USER_SERVICE",
            user_id="12345"
        )
    """
    global _rabbitmq_port_instance

    if _rabbitmq_port_instance is None:
        logger.info("Creating RabbitMQ port instance")
        rabbitmq_singleton = await get_rabbitmq_instance()
        _rabbitmq_port_instance = RabbitMQPort(rabbitmq_singleton)
        logger.info("RabbitMQ port instance created and cached")

    return _rabbitmq_port_instance
