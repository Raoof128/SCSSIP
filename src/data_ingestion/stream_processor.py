"""
Stream processing infrastructure for security events.
Handles Kafka/Redis streaming, buffering, and batching.
"""

import asyncio
import json
from typing import AsyncIterator, Dict, Any, List, Optional, Callable
from datetime import datetime
from abc import ABC, abstractmethod
from loguru import logger

# Import conditionally to handle missing dependencies gracefully
try:
    from kafka import KafkaProducer, KafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KafkaProducer = None
    KafkaConsumer = None
    KAFKA_AVAILABLE = False
    logger.warning("kafka-python not available, Kafka streaming disabled")

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
    REDIS_ASYNC = True
except ImportError:
    try:
        import redis
        aioredis = redis
        REDIS_AVAILABLE = True
        REDIS_ASYNC = False
    except ImportError:
        redis = None
        aioredis = None
        REDIS_AVAILABLE = False
        REDIS_ASYNC = False
        logger.warning("redis not available, Redis streaming disabled")


class StreamProcessor(ABC):
    """Abstract base class for stream processors."""

    @abstractmethod
    async def produce(self, topic: str, message: Dict[str, Any]) -> None:
        """Produce message to stream."""
        pass

    @abstractmethod
    async def consume(self, topic: str, callback: Callable) -> None:
        """Consume messages from stream."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close stream processor."""
        pass


class KafkaStreamProcessor(StreamProcessor):
    """Kafka-based stream processor."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Kafka stream processor.

        Args:
            config: Kafka configuration
        """
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python required for Kafka streaming")

        self.config = config
        self.bootstrap_servers = config.get('bootstrap_servers', 'localhost:9092')
        self.consumer_group = config.get('consumer_group', 'threat-hunting-platform')

        self.producer = None
        self.consumers: Dict[str, KafkaConsumer] = {}

        logger.info(f"Initialized Kafka stream processor: {self.bootstrap_servers}")

    async def produce(self, topic: str, message: Dict[str, Any]) -> None:
        """
        Produce message to Kafka topic.

        Args:
            topic: Kafka topic name
            message: Message dictionary
        """
        if self.producer is None:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )

        try:
            future = self.producer.send(topic, message)
            # Wait for send to complete (non-blocking with timeout)
            await asyncio.get_event_loop().run_in_executor(None, future.get, 10)

        except Exception as e:
            logger.error(f"Failed to produce message to Kafka topic {topic}: {e}")
            raise

    async def consume(self, topic: str, callback: Callable) -> None:
        """
        Consume messages from Kafka topic.

        Args:
            topic: Kafka topic name
            callback: Async callback function for each message
        """
        if topic not in self.consumers:
            self.consumers[topic] = KafkaConsumer(
                topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.consumer_group,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=False
            )

        consumer = self.consumers[topic]

        try:
            logger.info(f"Starting Kafka consumer for topic: {topic}")

            while True:
                # Poll for messages
                messages = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: consumer.poll(timeout_ms=1000, max_records=100)
                )

                for topic_partition, records in messages.items():
                    for record in records:
                        try:
                            await callback(record.value)
                        except Exception as e:
                            logger.error(f"Error processing Kafka message: {e}")

                    # Commit offsets after processing batch
                    consumer.commit()

                # Yield control to event loop
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"Error consuming from Kafka topic {topic}: {e}")
            raise

    async def close(self) -> None:
        """Close Kafka connections."""
        if self.producer:
            self.producer.close()

        for consumer in self.consumers.values():
            consumer.close()

        logger.info("Closed Kafka stream processor")


class RedisStreamProcessor(StreamProcessor):
    """Redis Streams-based processor."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Redis stream processor.

        Args:
            config: Redis configuration
        """
        if not REDIS_AVAILABLE:
            raise ImportError("redis required for Redis streaming")

        self.config = config
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 6379)
        self.password = config.get('password')
        self.db = config.get('db', 0)

        self.client = None
        self.consumer_tasks: Dict[str, asyncio.Task] = {}

        logger.info(f"Initialized Redis stream processor: {self.host}:{self.port}")

    async def _get_client(self):
        """Get or create Redis client."""
        if self.client is None:
            if REDIS_ASYNC:
                self.client = await aioredis.create_redis_pool(
                    f'redis://{self.host}:{self.port}',
                    password=self.password,
                    db=self.db,
                    encoding='utf-8'
                )
            else:
                # Fallback to sync Redis
                self.client = aioredis.Redis(
                    host=self.host,
                    port=self.port,
                    password=self.password,
                    db=self.db,
                    decode_responses=True
                )
        return self.client

    async def produce(self, stream: str, message: Dict[str, Any]) -> None:
        """
        Produce message to Redis stream.

        Args:
            stream: Redis stream name
            message: Message dictionary
        """
        try:
            client = await self._get_client()

            # Serialize message
            message_data = {'data': json.dumps(message)}

            # Add to stream
            await client.xadd(stream, message_data)

        except Exception as e:
            logger.error(f"Failed to produce message to Redis stream {stream}: {e}")
            raise

    async def consume(self, stream: str, callback: Callable) -> None:
        """
        Consume messages from Redis stream.

        Args:
            stream: Redis stream name
            callback: Async callback function for each message
        """
        try:
            client = await self._get_client()

            logger.info(f"Starting Redis consumer for stream: {stream}")

            # Create consumer group if it doesn't exist
            try:
                await client.xgroup_create(stream, 'threat-hunting-platform', mkstream=True)
            except Exception:
                pass  # Group might already exist

            # Read messages
            last_id = '0-0'

            while True:
                # Read from stream
                messages = await client.xread([stream], latest_ids=[last_id], count=100, timeout=1000)

                for stream_name, stream_messages in messages:
                    for message_id, message_data in stream_messages:
                        try:
                            # Deserialize and process message
                            data = json.loads(message_data[b'data'].decode('utf-8'))
                            await callback(data)
                            last_id = message_id

                        except Exception as e:
                            logger.error(f"Error processing Redis message: {e}")

                # Yield control to event loop
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"Error consuming from Redis stream {stream}: {e}")
            raise

    async def close(self) -> None:
        """Close Redis connections."""
        if self.client:
            self.client.close()
            await self.client.wait_closed()

        logger.info("Closed Redis stream processor")


class EventBuffer:
    """
    Buffer for batching security events before processing.
    Implements time-based and size-based flushing.
    """

    def __init__(
        self,
        max_size: int = 1000,
        max_age_seconds: int = 60,
        flush_callback: Optional[Callable] = None
    ):
        """
        Initialize event buffer.

        Args:
            max_size: Maximum buffer size before auto-flush
            max_age_seconds: Maximum age of oldest event before auto-flush
            flush_callback: Async callback to invoke on flush
        """
        self.max_size = max_size
        self.max_age_seconds = max_age_seconds
        self.flush_callback = flush_callback

        self.buffer: List[Dict[str, Any]] = []
        self.oldest_event_time: Optional[datetime] = None
        self._lock = asyncio.Lock()

        logger.info(f"Initialized event buffer: max_size={max_size}, max_age={max_age_seconds}s")

    async def add(self, event: Dict[str, Any]) -> None:
        """
        Add event to buffer.

        Args:
            event: Event dictionary
        """
        async with self._lock:
            self.buffer.append(event)

            if self.oldest_event_time is None:
                self.oldest_event_time = datetime.utcnow()

            # Check if flush needed
            should_flush = (
                len(self.buffer) >= self.max_size or
                (datetime.utcnow() - self.oldest_event_time).total_seconds() >= self.max_age_seconds
            )

            if should_flush:
                await self.flush()

    async def flush(self) -> List[Dict[str, Any]]:
        """
        Flush buffer and return events.

        Returns:
            List of buffered events
        """
        async with self._lock:
            if not self.buffer:
                return []

            events = self.buffer.copy()
            self.buffer.clear()
            self.oldest_event_time = None

            logger.debug(f"Flushed {len(events)} events from buffer")

            # Invoke callback if provided
            if self.flush_callback:
                try:
                    await self.flush_callback(events)
                except Exception as e:
                    logger.error(f"Error in flush callback: {e}")

            return events

    async def size(self) -> int:
        """Get current buffer size."""
        async with self._lock:
            return len(self.buffer)
