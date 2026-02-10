import redis
import logging
from typing import Optional, Any
from time import sleep
from functools import wraps

# Настройка логирования
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class StoreConnectionError(Exception):
    """Исключение для ошибок соединения с хранилищем"""
    pass


class Store:
    def __init__(
            self,
            host: str = 'localhost',
            port: int = 6379,
            db: int = 0,
            socket_timeout: float = 0.1,
            socket_connect_timeout: float = 0.1,
            retry_attempts: int = 3,
            retry_delay: float = 0.1
    ):
        """
        Инициализация Redis хранилища

        Args:
            host: хост Redis
            port: порт Redis
            db: номер базы данных
            socket_timeout: таймаут операций в секундах
            socket_connect_timeout: таймаут подключения в секундах
            retry_attempts: количество попыток переподключения
            retry_delay: задержка между попытками в секундах
        """
        self.host = host
        self.port = port
        self.db = db
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self._client = None
        self._connect()

    def _connect(self) -> None:
        """Установка соединения с Redis"""
        for attempt in range(self.retry_attempts):
            try:
                self._client = redis.Redis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    socket_timeout=self.socket_timeout,
                    socket_connect_timeout=self.socket_connect_timeout,
                    decode_responses=True,  # Автоматически декодировать bytes в str
                    retry_on_timeout=True,  # Повторять при таймаутах
                    health_check_interval=30  # Проверять здоровье соединения
                )
                # Проверяем соединение
                self._client.ping()
                logger.info(f"Успешное подключение к Redis {self.host}:{self.port}")
                return
            except (redis.ConnectionError, redis.TimeoutError) as e:
                logger.warning(f"Попытка {attempt + 1}/{self.retry_attempts} не удалась: {e}")
                if attempt < self.retry_attempts - 1:
                    sleep(self.retry_delay)
                else:
                    logger.error(f"Не удалось подключиться к Redis после {self.retry_attempts} попыток")
                    raise StoreConnectionError(f"Не удалось подключиться к Redis: {e}")

    def _ensure_connection(func):
        """Декоратор для обеспечения активного соединения"""

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            for attempt in range(self.retry_attempts):
                try:
                    # Проверяем соединение
                    if self._client is None:
                        self._connect()
                    return func(self, *args, **kwargs)
                except (redis.ConnectionError, redis.TimeoutError, AttributeError) as e:
                    logger.warning(f"Ошибка соединения в {func.__name__}, попытка {attempt + 1}: {e}")
                    if attempt < self.retry_attempts - 1:
                        try:
                            # Пытаемся переподключиться
                            self._connect()
                        except StoreConnectionError:
                            pass
                        sleep(self.retry_delay)
                    else:
                        # Для cache_get не выбрасываем исключение, для get - выбрасываем
                        if func.__name__ in ['cache_get', 'cache_set']:
                            return None
                        else:
                            raise StoreConnectionError(
                                f"Не удалось выполнить {func.__name__} после {self.retry_attempts} попыток")

        return wrapper

    @_ensure_connection
    def get(self, key: str) -> Optional[str]:
        """
        Получение значения по ключу из персистентного хранилища

        Args:
            key: ключ для получения

        Returns:
            Значение или None, если ключ не найден

        Raises:
            StoreConnectionError: если не удалось подключиться к хранилищу
        """
        try:
            value = self._client.get(key)
            return value
        except redis.RedisError as e:
            logger.error(f"Ошибка при получении ключа {key}: {e}")
            raise StoreConnectionError(f"Ошибка при получении данных: {e}")

    @_ensure_connection
    def cache_get(self, key: str) -> Optional[Any]:
        """
        Получение значения из кэша

        Args:
            key: ключ для получения

        Returns:
            Значение или None, если ключ не найден или произошла ошибка
        """
        try:
            value = self._client.get(key)
            if value is not None:
                # Пытаемся преобразовать в float, если это число
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return value
            return None
        except redis.RedisError as e:
            logger.warning(f"Ошибка кэша при получении ключа {key}: {e}")
            return None  # Для cache_get всегда возвращаем None при ошибках

    @_ensure_connection
    def cache_set(self, key: str, value: Any, ttl: int = 0) -> bool:
        """
        Установка значения в кэш с TTL

        Args:
            key: ключ
            value: значение
            ttl: время жизни в секундах

        Returns:
            True если успешно, False в противном случае
        """
        try:
            if ttl > 0:
                result = self._client.setex(key, ttl, str(value))
            else:
                result = self._client.set(key, str(value))
            return result is True
        except redis.RedisError as e:
            logger.warning(f"Ошибка кэша при установке ключа {key}: {e}")
            return False  # Для cache_set всегда возвращаем False при ошибках

    @_ensure_connection
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Установка значения в персистентное хранилище

        Args:
            key: ключ
            value: значение
            ttl: время жизни в секундах (опционально)

        Returns:
            True если успешно

        Raises:
            StoreConnectionError: если не удалось подключиться к хранилищу
        """
        try:
            if ttl is not None and ttl > 0:
                result = self._client.setex(key, ttl, value)
            else:
                result = self._client.set(key, value)
            return result is True
        except redis.RedisError as e:
            logger.error(f"Ошибка при установке ключа {key}: {e}")
            raise StoreConnectionError(f"Ошибка при сохранении данных: {e}")

    def close(self) -> None:
        """Закрытие соединения с Redis"""
        if self._client is not None:
            try:
                self._client.close()
                logger.info("Соединение с Redis закрыто")
            except Exception as e:
                logger.error(f"Ошибка при закрытии соединения: {e}")
            finally:
                self._client = None


# Фабричная функция для создания экземпляра хранилища
def get_store(
        host: str = 'localhost',
        port: int = 6379,
        db: int = 0,
        **kwargs
) -> Store:
    """
    Создание экземпляра хранилища

    Args:
        host: хост Redis
        port: порт Redis
        db: номер базы данных
        **kwargs: дополнительные параметры для Store

    Returns:
        Экземпляр Store
    """
    return Store(host=host, port=port, db=db, **kwargs)