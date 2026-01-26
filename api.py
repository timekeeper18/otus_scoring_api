import datetime
import hashlib
import json
import logging
import uuid
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)
from typing import Any, Callable, Optional

import src.scoring as scoring


class Gender(Enum):
    """Enumeration for gender values.

    Attributes:
        UNKNOWN: Gender not specified (value: 0).
        MALE: Male gender (value: 1).
        FEMALE: Female gender (value: 2).
    """
    UNKNOWN = 0
    MALE = 1
    FEMALE = 2


class ErrorMessage(Enum):
    """Список для HTTP error сообщений.

    Attributes:
        BAD_REQUEST: Bad Request error message.
        FORBIDDEN: Forbidden error message.
        NOT_FOUND: Not Found error message.
        INVALID_REQUEST: Invalid Request error message.
        INTERNAL_ERROR: Internal Server Error message.
    """
    BAD_REQUEST = "Bad Request"
    FORBIDDEN = "Forbidden"
    NOT_FOUND = "Not Found"
    INVALID_REQUEST = "Invalid Request"
    INTERNAL_ERROR = "Internal Server Error"


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500

ERRORS = {
    BAD_REQUEST: ErrorMessage.BAD_REQUEST.value,
    FORBIDDEN: ErrorMessage.FORBIDDEN.value,
    NOT_FOUND: ErrorMessage.NOT_FOUND.value,
    INVALID_REQUEST: ErrorMessage.INVALID_REQUEST.value,
    INTERNAL_ERROR: ErrorMessage.INTERNAL_ERROR.value,
}


class ValidationError(Exception):
    pass


class Field(ABC):
    """Абстрактный базовый класс для проверки полей.

    Attributes:
        required (bool): признак обязательности.
        nullable (bool): признак пустого значения null.
    """

    def __init__(self, required: bool = False, nullable: bool = True) -> None:
        """Инициализация объекта Field.

        Args:
            required: признак обязательности.
            nullable: признак пустого значения null.
        """
        self.required = required
        self.nullable = nullable

    @abstractmethod
    def validate(self, value: Any) -> bool:
        """Проверка значения поля.

        Args:
            value: значение для проверки.

        Returns:
            bool: True если корректно, False если нет.

        Note:
            метод должен быть реализован в наследниках.
        """
        pass

    def is_valid(self, value: Any) -> tuple[bool, Optional[str]]:
        """Проверка обязательности и наличия пустого значения.

        Args:
            value: значение для проверки.

        Returns:
            Tuple containing:
                - bool: True если корректно, False если нет
                - Optional[str]: None если корректно, сообщение об ошибке, если нет

        Note:
            проверка required/nullable до вызова функции validate().
        """
        if value is None:
            if self.required:
                return False, "Field is required"
            if not self.nullable:
                return False, "Field cannot be null"
            return True, None

        return self.validate(value), None


class CharField(Field):
    """Строковое поле."""

    def validate(self, value: Any) -> bool:
        """Проверка, что значение - строка.

        Args:
            value: значение для проверки.

        Returns:
            bool: True если корректно, False если нет.
        """
        return isinstance(value, str)


class ArgumentsField(Field):
    """Поле для типа словарь."""

    def validate(self, value: Any) -> bool:
        """Проверка, что значение - dictionary.

        Args:
            value: значение для проверки.

        Returns:
            bool: True если корректно, False если нет.
        """
        return isinstance(value, dict)


class EmailField(CharField):
    """Поле для email адреса."""

    def validate(self, value: Any) -> bool:
        """Проверка формата email.

        Args:
            value: значение для проверки.

        Returns:
            bool: True если корректно, False если нет.

        Note:
            Email must be a string and contain '@' character.
        """
        if not super().validate(value):
            return False
        return '@' in value


class PhoneField(Field):
    """Поле для телефона."""

    def validate(self, value: Any) -> bool:
        """Проверка формата номера телефона.

        Args:
            value: значение для проверки.

        Returns:
            bool: True если корректно, False если нет.

        Note:
            Номер дллжен содержать 11 цифр и начинаться с 7.
            Может быть как строкой, таи и числом.
        """
        if not isinstance(value, (str, int)):
            return False

        str_value = str(value)
        if len(str_value) != 11:
            return False
        if not str_value.startswith('7'):
            return False
        return str_value.isdigit()


class DateField(Field):
    """Поле для даты формата DD.MM.YYYY."""

    def validate(self, value: Any) -> bool:
        """Проверка формата даты.

        Args:
            value: значение для проверки.

        Returns:
           bool: True если корректно: формат DD.MM.YYYY, False если нет.
        """
        if not isinstance(value, str):
            return False
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
            return True
        except ValueError:
            return False


class BirthDayField(DateField):
    """Поле для даты рождения и возраста."""

    def validate(self, value: Any) -> bool:
        """Проверка даты рождения с учетом возраста.

        Args:
            value: Значение для провкрки.

        Returns:
            bool: True если корректно: date and age is между 0 и 70, False если нет.
        """
        if not super().validate(value):
            return False

        birth_date = datetime.datetime.strptime(value, '%d.%m.%Y')
        age = (datetime.datetime.now() - birth_date).days / 365.25
        return 0 <= age < 70


class GenderField(Field):
    """Поле для пола."""

    def validate(self, value: Any) -> bool:
        """Проверка пола.

        Args:
            value: Значение для проверки.

        Returns:
            bool: True если корректно: gender (0, 1, or 2), False если нет.
        """
        if not isinstance(value, int):
            return False
        return value in [gender.value for gender in Gender]


class ClientIDsField(Field):
    """Поле для идентификатора."""

    def validate(self, value: Any) -> bool:
        """Проверка списка идентификаторов.

        Args:
            value: Список идентификаторов.

        Returns:
            bool: True если корректно: не пустой список integers, False если нет.
        """
        if not isinstance(value, list):
            return False
        if not value:
            return False
        return all(isinstance(item, int) for item in value)


class BaseRequest(ABC):
    """Абстрактный базовый класс для проверки запроса.

    Attributes:
        errors (dict): Словарь ошибок проверки.
    """

    def __init__(self, data: dict) -> None:
        """Инициализация объекта BaseRequest и проверка данных.

        Args:
            data: Словарь с данными запроса.
        """
        self.errors: dict[str, str] = {}
        self._validate(data)

    def _validate(self, data: dict) -> None:
        """Проверка данных запроса в соответствии с полями.

        Args:
            data: Словарь с данными запроса.

        Note:
           Проверка всех полей, определенных как атрибуты класса.
        """
        for field_name in dir(self):
            if field_name.startswith('_'):
                continue

            field = getattr(self, field_name)
            if isinstance(field, Field):
                value = data.get(field_name)
                is_valid, error = field.is_valid(value)
                if not is_valid:
                    self.errors[field_name] = error or "Invalid value"

    def is_valid(self) -> bool:
        """Проверка корректности данных.

        Returns:
            bool: True если корректно, False если нет.
        """
        return len(self.errors) == 0


class ClientsInterestsRequest(BaseRequest):
    """Класс запроса для метода clients_interests.

    Attributes:
        client_ids (ClientIDsField): Required список идентификаторов.
        date (DateField): Optional дата.
    """

    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, data: dict) -> None:
        """Инициализация объекта ClientsInterestsRequest.

        Args:
            data: словарь идентификаторов и дат.
        """
        super().__init__(data)
        if self.is_valid():
            self.client_ids = data.get('client_ids')
            self.date = data.get('date')


class OnlineScoreRequest(BaseRequest):
    """Класс запроса для метода online_score.

    Attributes:
        first_name (CharField): Optional имя.
        last_name (CharField): Optional фамилия.
        email (EmailField): Optional email адрес.
        phone (PhoneField): Optional номер телефона.
        birthday (BirthDayField): Optional дата рождения.
        gender (GenderField): Optional пол.
    """

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, data: dict) -> None:
        """Инициализация объекта OnlineScoreRequest.

        Args:
            data: Словарь с параметрами оценки.
        """
        super().__init__(data)
        if self.is_valid():
            self.first_name = data.get('first_name')
            self.last_name = data.get('last_name')
            self.email = data.get('email')
            self.phone = data.get('phone')
            self.birthday = data.get('birthday')
            self.gender = data.get('gender')

    def get_score_pairs(self) -> list:
        """Определение корректных пар для калькулятора.

        Returns:
            list: Список валидных пар.

        Note:
            корректные пары: (first_name, last_name), (gender, birthday).
        """
        pairs = []
        if self.phone and self.email:
            pairs.append(('phone', 'email'))
        if self.first_name and self.last_name:
            pairs.append(('first_name', 'last_name'))
        if self.gender is not None and self.birthday:
            pairs.append(('gender', 'birthday'))
        return pairs


class MethodRequest(BaseRequest):
    """Класс для вызова API метода.

    Attributes:
        account (CharField): Optional имя аккаунта.
        login (CharField): Required логин.
        token (CharField): Required токен аутентификации.
        arguments (ArgumentsField): Required аргументы метода.
        method (CharField): Required наименование метода.
    """

    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, data: dict):
        """Инициализация объекта MethodRequest.

        Args:
            data: словарь с данныеми запроса.
        """
        super().__init__(data)
        if self.is_valid():
            self.account = data.get('account')
            self.login = data.get('login')
            self.token = data.get('token')
            self.arguments = data.get('arguments')
            self.method = data.get('method')

    @property
    def is_admin(self) -> bool:
        """Проверка, являкется ли пользователь админом

        Returns:
            True если админ, False если нет.
        """
        return self.login == ADMIN_LOGIN


def check_auth(request: MethodRequest) -> bool:
    """Проверка токена авторизации.

    Args:
        request: объект MethodRequest, содержащий данные авторизации.

    Returns:
        True если аутентификация пройдена, False если нет.

    Note:
        Для админа: token должен быть HA512 hash текущего часа + ADMIN_SALT.
        Для обычного пользователя: token должен быть SHA512 hash (account + login + SALT).
    """
    if request.is_admin:
        # Для админа токен зависит от текущего часа
        # проверяем несколько возможных часов для учета возможной разницы во времени
        for hour_offset in [0, -1, 1]:  # текущий час, предыдущий, следующий
            check_time = datetime.datetime.now() + datetime.timedelta(hours=hour_offset)
            digest = hashlib.sha512(
                (check_time.strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")
            ).hexdigest()
            if digest == request.token:
                return True
        return False
    else:
        account = request.account or ""
        digest = hashlib.sha512(
            (account + request.login + SALT).encode("utf-8")
        ).hexdigest()
        return digest == request.token


def online_score_handler(request: OnlineScoreRequest, ctx: dict, store, is_admin: bool = False):
    """Обработка запросов к методу online_score.

    Args:
        request: Объект OnlineScoreRequest.
        ctx: Метаданные запроса.
        store: Storage объект.
        is_admin: Был ли запрос сделан Админом.

    Returns:
        Tuple containing:
            - dict: Данные с интересами клиента
            - int: HTTP статус код

    Raises:
        ValidationError: Если найдено не валидное значение для не админа.

    Note:
        Пользователь Админ всегда получает оценку 42.
        Контекст обновляется ключом 'has' - список заполненых полей.
    """
    if is_admin:
        logging.info(f"Admin score request - returning 42")
        return {"score": 42}, OK

    pairs = request.get_score_pairs()
    if not pairs:
        raise ValidationError("No valid field pairs found")

    # Используем функцию из scoring.py
    score = scoring.get_score(
        phone=request.phone,
        email=request.email,
        birthday=request.birthday,
        gender=request.gender,
        first_name=request.first_name,
        last_name=request.last_name
    )

    # Добавляем информацию о заполненных полях в контекст
    ctx['has'] = []
    if request.first_name:
        ctx['has'].append('first_name')
    if request.last_name:
        ctx['has'].append('last_name')
    if request.email:
        ctx['has'].append('email')
    if request.phone:
        ctx['has'].append('phone')
    if request.birthday:
        ctx['has'].append('birthday')
    if request.gender is not None:
        ctx['has'].append('gender')

    logging.info(f"Score calculated: {score} for pairs: {pairs}, filled fields: {ctx['has']}")
    return {"score": float(score)}, OK


def clients_interests_handler(request: ClientsInterestsRequest, ctx: dict, store):
    """Обработка запросов к методу clients_interests.

    Args:
        request: Объект ClientsInterestsRequest.
        ctx: Метаданные запроса.
        store: Storage объект.

    Returns:
        Tuple containing:
            - dict: Данные с интересами клиента
            - int: HTTP статус код

    Note:
        Контекст обновляется ключом 'nclients' - количеством клиентов.
    """
    result = {}
    for client_id in request.client_ids:
        # Используем функцию из scoring.py
        interests = scoring.get_interests(str(client_id))
        result[str(client_id)] = interests

    ctx['nclients'] = len(request.client_ids)
    logging.info(f"Clients interests request for {len(request.client_ids)} clients")
    return result, OK


def method_handler(
        request: dict[str, Any],
        ctx: dict[str, Any],
        store=None
) -> tuple[dict[str, Any], int]:
    """Основной handler запросов для API методов.

    Args:
        request: Словарь с данными запроса и заголовка.
        ctx: Словарь контекста для хранения метаданных щапроса.
        store: Storage объект (опционально).

    Returns:
        Tuple containing:
            - dict: Данные ответа или ошибка
            - int: HTTP статус код

    Note:
        Валидация запроса, аутентификация и маршрутизация методом.
        Генерация ID, если не передан.
        Логирование шагов запроса
    """
    try:
        # Извлекаем данные из запроса
        body = request.get("body", {})

        # Логируем полученный запрос
        request_id = ctx.get("request_id", "unknown")
        if request_id == "unknown":
            request_id = uuid.uuid4().hex
            ctx["request_id"] = request_id

        logging.info(f"Request ID: {request_id}, Received request: {json.dumps(body, ensure_ascii=False)[:200]}")

        # Валидируем основной запрос
        method_request = MethodRequest(body)
        if not method_request.is_valid():
            logging.warning(f"Request ID: {request_id}, Invalid method request: {method_request.errors}")
            # Возвращаем строку с ошибками, как требует спецификация
            error_msg = "; ".join([f"{k}: {v}" for k, v in method_request.errors.items()])
            return {"error": error_msg}, INVALID_REQUEST

        # Логируем успешную валидацию основного запроса
        logging.info(f"Request ID: {request_id}, Method: {method_request.method}, Login: {method_request.login}")

        # Проверяем авторизацию
        if not check_auth(method_request):
            logging.warning(f"Request ID: {request_id}, Auth failed for login: {method_request.login}")
            return {"error": "Forbidden"}, FORBIDDEN

        logging.info(f"Request ID: {request_id}, Auth successful for login: {method_request.login}")

        # Обрабатываем метод
        if method_request.method == "online_score":
            logging.info(
                f"Request ID: {request_id}, Processing online_score with arguments: {method_request.arguments}")
            score_request = OnlineScoreRequest(method_request.arguments or {})
            if not score_request.is_valid():
                logging.warning(f"Request ID: {request_id}, Invalid score request: {score_request.errors}")
                error_msg = "; ".join([f"{k}: {v}" for k, v in score_request.errors.items()])
                return {"error": error_msg}, INVALID_REQUEST
            return online_score_handler(score_request, ctx, store, method_request.is_admin)

        elif method_request.method == "clients_interests":
            logging.info(
                f"Request ID: {request_id}, Processing clients_interests with arguments: {method_request.arguments}")
            interests_request = ClientsInterestsRequest(method_request.arguments or {})
            if not interests_request.is_valid():
                logging.warning(f"Request ID: {request_id}, Invalid interests request: {interests_request.errors}")
                error_msg = "; ".join([f"{k}: {v}" for k, v in interests_request.errors.items()])
                return {"error": error_msg}, INVALID_REQUEST
            return clients_interests_handler(interests_request, ctx, store)

        else:
            logging.warning(f"Request ID: {request_id}, Unknown method: {method_request.method}")
            return {"error": f"Unknown method: {method_request.method}"}, INVALID_REQUEST

    except ValidationError as e:
        request_id = ctx.get('request_id', 'unknown')
        logging.warning(f"Request ID: {request_id}, Validation error: {str(e)}")
        return {"error": str(e)}, INVALID_REQUEST
    except Exception as e:
        request_id = ctx.get("request_id", "unknown")
        logging.exception(f"Request ID: {request_id}, Unexpected error in method_handler: {str(e)}")
        return {"error": "Internal server error"}, INTERNAL_ERROR


class MainHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler для scoring API.

    Attributes:
        router (dict): URL конфигуратор.
    """

    router: dict[str, Callable] = {"method": method_handler}

    def get_request_id(self, headers) -> str:
        """ Поучение ID из запроса, если нет, то генерация

        Args:
            headers: объект HTTP header.

        Returns:
            str: Request Идентификатор.

        Note:
            Читает заголовки.
            Генерирует UUID если он не пришел.
        """
        # В BaseHTTPRequestHandler заголовки доступны через self.headers
        request_id = headers.get('X-Request-Id')
        if not request_id:
            # Также проверяем другие возможные варианты написания
            request_id = headers.get('X-Request-ID')
        if not request_id:
            request_id = uuid.uuid4().hex
        return request_id

    def do_POST(self) -> None:
        """Handles POST запроса.

        Note:
            Обрабатывает JSON запрос, перенаправляет на соответствующий handler,
            логирует запросы и ответы, и отправляет HTTP запрос.
        """
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}

        # Логируем входящий запрос
        logging.info(f"=== Incoming POST request ===")
        logging.info(f"Request ID: {context['request_id']}")
        logging.info(f"Path: {self.path}")

        request: dict[str, Any] | None = None
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length:
                data_string = self.rfile.read(content_length)
                logging.info(f"Request body length: {len(data_string)} bytes")
                request = json.loads(data_string)
                logging.info(f"Request body (parsed): {json.dumps(request, ensure_ascii=False)[:200]}...")
            else:
                logging.warning(f"Request ID: {context['request_id']}, Empty request body")
        except json.JSONDecodeError as e:
            logging.error(f"Request ID: {context['request_id']}, JSON decode error: {str(e)}")
            code = BAD_REQUEST
            response = {"error": "Invalid JSON"}
        except Exception as e:
            logging.error(f"Request ID: {context['request_id']}, Error reading request: {str(e)}")
            code = BAD_REQUEST
            response = {"error": "Bad Request"}

        if request:
            path = self.path.strip("/")
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context,
                        None  # store передается как None, т.к. в scoring.py он не используется
                    )
                except Exception as e:
                    logging.exception(f"Request ID: {context['request_id']}, Unexpected error: {e}")
                    code = INTERNAL_ERROR
                    response = {"error": "Internal Server Error"}
            else:
                logging.warning(f"Request ID: {context['request_id']}, Path not found: {path}")
                code = NOT_FOUND
                response = {"error": "Not Found"}

        # Логируем ответ
        logging.info(f"Request ID: {context['request_id']}, Response code: {code}")
        if code == OK:
            logging.info(
                f"Request ID: {context['request_id']}, Response: {json.dumps(response, ensure_ascii=False)[:200]}...")

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response.get("error", ERRORS.get(code, "Unknown Error")), "code": code}

        context.update(r)
        logging.info(f"=== End of request processing ===\n")

        self.wfile.write(json.dumps(r).encode("utf-8"))

    def log_message(self, format, *args):
        """Переопределяем стандартное логирование BaseHTTPRequestHandler,
            чтобы использовать наше конфигурирование логирования

        Args:
            format: Сообщение доя логирования
            *args: аргументы форматирования.
        """
        #
        logging.info(f"HTTP: {format % args}")


if __name__ == "__main__":
    """Точка входа для запуска HTTP server."""
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(
        filename=args.log,
        level=log_level,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )

    # Если файл лога не указан, выводим логи в консоль
    if not args.log:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname).1s %(message)s",
            datefmt="%Y.%m.%d %H:%M:%S"
        ))
        logging.getLogger().addHandler(console_handler)

    server = HTTPServer(("localhost", args.port), MainHTTPHandler)

    logging.info(f"Starting server at port {args.port}")
    logging.info(f"Log level: {logging.getLevelName(log_level)}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception as e:
        logging.exception(f"Server error: {e}")
    finally:
        server.server_close()
        logging.info("Server closed")
