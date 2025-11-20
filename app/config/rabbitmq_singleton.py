import structlog
import aio_pika
import asyncio
from typing import Optional
from app.config.settings import settings

logger = structlog.get_logger()

class RabbitMQSingleton:
    """
    Singleton pattern for RabbitMQ connection.
    Ensures only one connection is maintained throughout the application lifecycle.
    """
    _instance: Optional["RabbitMQSingleton"] = None
    _connection: Optional[aio_pika.Connection] = None
    _channel: Optional[aio_pika.Channel] = None
    _exchange: Optional[aio_pika.Exchange] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RabbitMQSingleton, cls).__new__(cls)
        return cls._instance

    async def connect(self) -> None:
        """
        Establish connection to RabbitMQ server with timeout.
        """
        if self._connection is not None and not self._connection.is_closed:
            logger.info("RabbitMQ connection already established")
            return

        try:
            connection_url = f"amqp://{settings.RABBITMQ_USER}:{settings.RABBITMQ_PASSWORD}@{settings.RABBITMQ_HOST}:{settings.RABBITMQ_PORT}/"
            # Add 5 second timeout to prevent app from hanging
            self._connection = await asyncio.wait_for(
                aio_pika.connect_robust(connection_url),
                timeout=5.0
            )
            logger.info(
                "RabbitMQ connection established",
                host=settings.RABBITMQ_HOST,
                port=settings.RABBITMQ_PORT,
                user=settings.RABBITMQ_USER
            )
        except asyncio.TimeoutError:
            logger.error(
                "RabbitMQ connection timeout",
                host=settings.RABBITMQ_HOST,
                port=settings.RABBITMQ_PORT,
                timeout_seconds=5.0
            )
            raise
        except Exception as e:
            logger.exception("Failed to connect to RabbitMQ", error=str(e))
            raise

    async def get_channel(self) -> aio_pika.Channel:
        """
        Get or create a channel for the connection.
        """
        if self._connection is None or self._connection.is_closed:
            await self.connect()

        if self._channel is None or self._channel.is_closed:
            self._channel = await self._connection.channel()
            logger.info("RabbitMQ channel created")

        return self._channel

    async def get_exchange(self) -> aio_pika.Exchange:
        """
        Get or declare the exchange for publishing messages.
        """
        if self._exchange is None:
            channel = await self.get_channel()
            self._exchange = await channel.declare_exchange(
                name=settings.RABBITMQ_EXCHANGE,
                type=aio_pika.ExchangeType.TOPIC,
                durable=True
            )
            logger.info(
                "RabbitMQ exchange declared",
                exchange=settings.RABBITMQ_EXCHANGE
            )

        return self._exchange

    async def disconnect(self) -> None:
        """
        Close RabbitMQ connection and cleanup resources.
        """
        if self._channel and not self._channel.is_closed:
            await self._channel.close()
            self._channel = None
            logger.info("RabbitMQ channel closed")

        if self._connection and not self._connection.is_closed:
            await self._connection.close()
            self._connection = None
            logger.info("RabbitMQ connection closed")


async def get_rabbitmq_instance() -> RabbitMQSingleton:
    """
    Factory function to get or create the RabbitMQ singleton instance.
    Does NOT establish connection - connection is lazy loaded on first use.
    """
    instance = RabbitMQSingleton()
    return instance
