import random
import hashlib
import json
from datetime import datetime
from typing import Optional


def get_score(
    store=None,
    phone: Optional[str] = None,
    email: Optional[str] = None,
    birthday: Optional[datetime] = None,
    gender: Optional[int] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
) -> float:
    """Calculate score with optional caching via store."""

    # Если store не передан, вычисляем score без кэширования
    if store is None:
        return _calculate_score(phone, email, birthday, gender, first_name, last_name)

    # Генерируем ключ для кэша
    key_parts = [
        first_name or "",
        last_name or "",
        phone or "",
        birthday.strftime("%Y%m%d") if birthday else "",
        str(gender) if gender is not None else "",
    ]
    key = "uid:" + hashlib.md5("".join(key_parts).encode('utf-8')).hexdigest()

    # Пытаемся получить из кэша, если store поддерживает cache_get
    if hasattr(store, 'cache_get'):
        cached_score = store.cache_get(key)
        if cached_score is not None:
            try:
                return float(cached_score)
            except (ValueError, TypeError):
                pass  # Если не можем преобразовать, вычисляем заново

    # Вычисляем score
    score = _calculate_score(phone, email, birthday, gender, first_name, last_name)

    # Сохраняем в кэш, если store поддерживает cache_set
    if hasattr(store, 'cache_set'):
        try:
            store.cache_set(key, score, 60 * 60)  # TTL 1 час
        except Exception:
            pass  # Игнорируем ошибки кэширования

    return score


def _calculate_score(
    phone: Optional[str] = None,
    email: Optional[str] = None,
    birthday: Optional[datetime] = None,
    gender: Optional[int] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
) -> float:
    """Calculate score without caching."""
    score = 0.0

    if phone:
        score += 1.5

    if email:
        score += 1.5

    if birthday and gender is not None:
        score += 1.5

    if first_name and last_name:
        score += 0.5

    return score


def get_interests(store=None, cid: Optional[str] = None) -> list[str]:
    """Get interests with optional storage support."""

    # Если cid не передан, возвращаем пустой список
    if cid is None:
        return []

    # Если store передан и поддерживает get, пытаемся получить из хранилища
    if store is not None and hasattr(store, 'get'):
        try:
            # Формируем ключ для хранилища
            key = f"i:{cid}"
            result = store.get(key)

            if result is not None:
                # Если результат уже список, возвращаем его
                if isinstance(result, list):
                    return result

                # Если результат - строка JSON, парсим ее
                if isinstance(result, str):
                    try:
                        return json.loads(result)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass  # Игнорируем ошибки при получении из хранилища

    # Если не получили из хранилища, генерируем случайные интересы
    interests = [
        "cars",
        "pets",
        "travel",
        "hi-tech",
        "sport",
        "music",
        "books",
        "tv",
        "cinema",
        "geek",
        "otus",
    ]

    return random.sample(interests, 2)