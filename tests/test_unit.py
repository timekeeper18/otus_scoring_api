import unittest
import datetime
import functools
import json
import hashlib
from unittest.mock import Mock
import sys
import os

# Добавляем src в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from api import (
    Field, CharField, ArgumentsField, EmailField, PhoneField,
    DateField, BirthDayField, GenderField, ClientIDsField,
    MethodRequest, OnlineScoreRequest, ClientsInterestsRequest,
    check_auth, method_handler,
    SALT, ADMIN_LOGIN, ADMIN_SALT
)
import scoring

def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)

        return wrapper

    return decorator

class TestFields(unittest.TestCase):
    """Тесты для классов полей валидации"""

    @cases([
        (None, True, True),
        (None, False, False),
        ("test", True, True),
        ("", True, True),
        (123, True, False),
        ([], True, False),
    ])
    def test_char_field(self, value, nullable, expected):
        field = CharField(required=False, nullable=nullable)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        ("test@example.com", True),
        ("invalid", False),
        (None, True),
        ("", False),  # Пустая строка не содержит @
        (123, False),
    ])
    def test_email_field(self, value, expected):
        field = EmailField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        ("79175002040", True),
        (79175002040, True),
        ("89175002040", False),  # должно начинаться с 7
        ("7917500204", False),  # меньше 11 цифр
        ("791750020401", False),  # больше 11 цифр
        ("7abcdefghij", False),  # не цифры
        (None, True),
    ])
    def test_phone_field(self, value, expected):
        field = PhoneField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        ("01.01.2000", True),
        ("31.12.1990", True),
        ("32.01.2000", False),  # неверный день
        ("01.13.2000", False),  # неверный месяц
        ("01-01-2000", False),  # неверный формат
        (None, True),
        ("", False),  # Пустая строка не является валидной датой
    ])
    def test_date_field(self, value, expected):
        field = DateField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        ("01.01.2000", True),  # возраст меньше 70
        ("01.01.1990", True),  # возраст около 36
        ("01.01.1955", False),  # возраст около 65
        ("01.01.1950", False),  # возраст больше 70
        ("01.01.1890", False),  # возраст больше 70
        ("01.01.2050", False),  # будущая дата
        (None, True),
    ])
    def test_birthday_field(self, value, expected):
        field = BirthDayField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        (0, True),  # UNKNOWN
        (1, True),  # MALE
        (2, True),  # FEMALE
        (-1, False),  # неверное значение
        (3, False),  # неверное значение
        ("1", False),  # строка вместо числа
        (None, True),
    ])
    def test_gender_field(self, value, expected):
        field = GenderField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)

    @cases([
        ([1, 2, 3], True),
        ([1], True),
        ([], False),  # пустой список
        ("[1,2,3]", False),  # не список
        ([1, "2", 3], False),  # не все элементы - int
        (None, True),
    ])
    def test_client_ids_field(self, value, expected):
        field = ClientIDsField(required=False, nullable=True)
        is_valid, error = field.is_valid(value)
        self.assertEqual(is_valid, expected)


class TestRequests(unittest.TestCase):
    """Тесты для классов запросов"""

    @cases([
        # Валидные запросы
        {
            "account": "test",
            "login": "user",
            "token": "token",
            "arguments": {"key": "value"},
            "method": "online_score"
        },
        # Без account (nullable)
        {
            "login": "user",
            "token": "token",
            "arguments": {},
            "method": "clients_interests"
        },
    ])
    def test_method_request_valid(self, data):
        request = MethodRequest(data)
        self.assertTrue(request.is_valid())

    @cases([
        # Без login (required)
        {
            "account": "test",
            "token": "token",
            "arguments": {},
            "method": "online_score"
        },
        # Без token (required)
        {
            "account": "test",
            "login": "user",
            "arguments": {},
            "method": "online_score"
        },
        # Без arguments (required)
        {
            "account": "test",
            "login": "user",
            "token": "token",
            "method": "online_score"
        },
        # Без method (required)
        {
            "account": "test",
            "login": "user",
            "token": "token",
            "arguments": {}
        },
    ])
    def test_method_request_invalid(self, data):
        request = MethodRequest(data)
        self.assertFalse(request.is_valid())
        self.assertGreater(len(request.errors), 0)

    @cases([
        {
            "phone": "79175002040",
            "email": "test@example.com"
        },
        {
            "first_name": "John",
            "last_name": "Doe"
        },
        {
            "gender": 1,
            "birthday": "01.01.2000"
        },
        {
            "phone": "79175002040",
            "email": "test@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "gender": 1,
            "birthday": "01.01.2000"
        },
    ])
    def test_online_score_request_valid(self, arguments):
        request = OnlineScoreRequest(arguments)
        self.assertTrue(request.is_valid())

    @cases([
        {"phone": "invalid"},
        {"email": "invalid"},
        {"gender": -1, "birthday": "01.01.2000"},
        {"birthday": "01.01.1890"},  # слишком старая дата
    ])
    def test_online_score_request_invalid(self, arguments):
        request = OnlineScoreRequest(arguments)
        self.assertFalse(request.is_valid())

    @cases([
        ({"client_ids": [1, 2, 3], "date": "20.07.2017"}),
        ({"client_ids": [1]}),
        ({"client_ids": [1, 2], "date": "01.01.2023"}),
    ])
    def test_clients_interests_request_valid(self, arguments):
        request = ClientsInterestsRequest(arguments)
        self.assertTrue(request.is_valid())

    @cases([
        {"client_ids": []},
        {"client_ids": "not_a_list"},
        {"client_ids": [1, 2], "date": "invalid_date"},
    ])
    def test_clients_interests_request_invalid(self, arguments):
        request = ClientsInterestsRequest(arguments)
        self.assertFalse(request.is_valid())


class TestAuth(unittest.TestCase):
    """Тесты для авторизации"""

    def setUp(self):
        self.valid_time = datetime.datetime.now()

    def test_admin_auth_valid(self):
        """Тест аутентификации администратора"""
        # Токен для текущего часа
        token = self._generate_admin_token(self.valid_time)
        request = MethodRequest({
            "login": ADMIN_LOGIN,
            "token": token,
            "arguments": {},
            "method": "online_score"
        })
        self.assertTrue(check_auth(request))

    def test_admin_auth_invalid(self):
        """Тест неверного токена администратора"""
        request = MethodRequest({
            "login": ADMIN_LOGIN,
            "token": "invalid_token",
            "arguments": {},
            "method": "online_score"
        })
        self.assertFalse(check_auth(request))

    def test_user_auth_valid(self):
        """Тест аутентификации обычного пользователя"""
        account = "test_account"
        login = "test_user"
        token = self._generate_user_token(account, login)

        request = MethodRequest({
            "account": account,
            "login": login,
            "token": token,
            "arguments": {},
            "method": "online_score"
        })
        self.assertTrue(check_auth(request))

    def test_user_auth_invalid(self):
        """Тест неверного токена пользователя"""
        request = MethodRequest({
            "account": "test",
            "login": "user",
            "token": "invalid_token",
            "arguments": {},
            "method": "online_score"
        })
        self.assertFalse(check_auth(request))

    @staticmethod
    def _generate_admin_token(time):
        """Генерация токена для администратора"""
        return hashlib.sha512((time.strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")).hexdigest()

    @staticmethod
    def _generate_user_token(account, login):
        """Генерация токена для пользователя"""
        return hashlib.sha512(((account or "") + login + SALT).encode("utf-8")).hexdigest()


class TestScoring(unittest.TestCase):
    """Тесты для функций скоринга"""

    def setUp(self):
        self.mock_store = Mock()
        self.mock_store.cache_get = Mock(return_value=None)
        self.mock_store.cache_set = Mock(return_value=True)
        self.mock_store.get = Mock(return_value=None)

    @cases([
        # Только телефон
        ({"phone": "79175002040"}, 1.5),
        # Только email
        ({"email": "test@example.com"}, 1.5),
        # Телефон и email
        ({"phone": "79175002040", "email": "test@example.com"}, 3.0),
        # Имя и фамилия
        ({"first_name": "John", "last_name": "Doe"}, 0.5),
        # Пол и дата рождения
        ({"gender": 1, "birthday": datetime.datetime(2000, 1, 1)}, 1.5),
        # Все поля
        ({
             "phone": "79175002040",
             "email": "test@example.com",
             "first_name": "John",
             "last_name": "Doe",
             "gender": 1,
             "birthday": datetime.datetime(2000, 1, 1)
         }, 5.0),
    ])
    def test_get_score_calculation(self, kwargs, expected_score):
        """Тест вычисления score без кэширования"""
        score = scoring.get_score(store=None, **kwargs)
        self.assertAlmostEqual(score, expected_score)

    def test_get_score_with_caching(self):
        """Тест кэширования score"""
        # Первый вызов - вычисляем и кэшируем
        score1 = scoring.get_score(
            store=self.mock_store,
            phone="79175002040",
            email="test@example.com"
        )

        # Проверяем, что cache_get был вызван
        self.mock_store.cache_get.assert_called()

        # Проверяем, что cache_set был вызван с правильными аргументами
        self.mock_store.cache_set.assert_called_once()
        args, kwargs = self.mock_store.cache_set.call_args
        self.assertEqual(len(args), 3)  # key, value, ttl
        self.assertAlmostEqual(args[1], 3.0)  # score значение

        # Сбрасываем моки
        self.mock_store.cache_get.reset_mock()
        self.mock_store.cache_set.reset_mock()

        # Настраиваем cache_get на возврат закэшированного значения
        self.mock_store.cache_get.return_value = 3.0

        # Второй вызов - должен получить из кэша
        score2 = scoring.get_score(
            store=self.mock_store,
            phone="79175002040",
            email="test@example.com"
        )

        # Проверяем, что cache_get был вызван
        self.mock_store.cache_get.assert_called()

        # Проверяем, что cache_set НЕ был вызван (берем из кэша)
        self.mock_store.cache_set.assert_not_called()

        self.assertAlmostEqual(score2, 3.0)

    def test_get_interests_with_store(self):
        """Тест получения интересов из store"""
        # Настраиваем store на возврат JSON строки
        test_interests = ["music", "books"]
        self.mock_store.get.return_value = json.dumps(test_interests)

        interests = scoring.get_interests(store=self.mock_store, cid="123")

        # Проверяем, что get был вызван с правильным ключом
        self.mock_store.get.assert_called_once_with("i:123")

        # Проверяем результат
        self.assertEqual(interests, test_interests)

    def test_get_interests_without_store(self):
        """Тест получения интересов без store"""
        interests = scoring.get_interests(store=None, cid="123")

        # Должен вернуть случайные интересы
        self.assertIsInstance(interests, list)
        self.assertEqual(len(interests), 2)
        self.assertTrue(all(isinstance(i, str) for i in interests))

    def test_get_interests_with_list_in_store(self):
        """Тест когда store возвращает список напрямую"""
        test_interests = ["sports", "movies"]
        mock_store = Mock()
        mock_store.get = Mock(return_value=test_interests)

        interests = scoring.get_interests(store=mock_store, cid="456")

        self.assertEqual(interests, test_interests)


class TestMethodHandler(unittest.TestCase):
    """Тесты для основного обработчика методов"""

    def setUp(self):
        self.context = {}
        self.store = {}

    def test_method_handler_online_score(self):
        """Тест обработки online_score"""
        request = {
            "account": "test",
            "login": "user",
            "method": "online_score",
            "arguments": {
                "phone": "79175002040",
                "email": "test@example.com"
            }
        }

        # Генерируем валидный токен
        token = hashlib.sha512(
            (request["account"] + request["login"] + SALT).encode()
        ).hexdigest()
        request["token"] = token

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 200)
        self.assertIn("score", response)
        self.assertIsInstance(response["score"], (int, float))
        self.assertIn("has", self.context)

    def test_method_handler_clients_interests(self):
        """Тест обработки clients_interests"""
        request = {
            "account": "test",
            "login": "user",
            "method": "clients_interests",
            "arguments": {
                "client_ids": [1, 2, 3],
                "date": "20.07.2017"
            }
        }

        # Генерируем валидный токен
        token = hashlib.sha512(
            (request["account"] + request["login"] + SALT).encode()
        ).hexdigest()
        request["token"] = token

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 200)
        self.assertEqual(len(response), 3)
        self.assertTrue(all(
            isinstance(v, list) and
            all(isinstance(i, str) for i in v)
            for v in response.values()
        ))
        self.assertEqual(self.context.get("nclients"), 3)

    def test_method_handler_admin_score(self):
        """Тест обработки запроса от администратора"""
        request = {
            "login": ADMIN_LOGIN,
            "method": "online_score",
            "arguments": {
                "phone": "79175002040",
                "email": "test@example.com"
            }
        }

        # Генерируем валидный токен администратора
        token = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()
        ).hexdigest()
        request["token"] = token

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 200)
        self.assertEqual(response["score"], 42)

    def test_method_handler_invalid_auth(self):
        """Тест обработки с неверной аутентификацией"""
        request = {
            "account": "test",
            "login": "user",
            "method": "online_score",
            "token": "invalid_token",
            "arguments": {}
        }

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 403)
        self.assertIn("error", response)

    def test_method_handler_invalid_request(self):
        """Тест обработки невалидного запроса"""
        request = {
            "account": "test",
            "login": "user",
            "method": "online_score",
            # Нет arguments - невалидно
        }

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 422)
        self.assertIn("error", response)

    def test_method_handler_unknown_method(self):
        """Тест обработки неизвестного метода"""
        request = {
            "account": "test",
            "login": "user",
            "method": "unknown_method",
            "arguments": {}
        }

        # Генерируем валидный токен
        token = hashlib.sha512(
            (request["account"] + request["login"] + SALT).encode()
        ).hexdigest()
        request["token"] = token

        response, code = method_handler(
            {"body": request},
            self.context,
            self.store
        )

        self.assertEqual(code, 422)
        self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main()