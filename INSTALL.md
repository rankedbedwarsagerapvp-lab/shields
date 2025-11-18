# Быстрая установка Shield с MySQL

## 1. Установка и настройка MySQL

**macOS:**
```bash
brew install mysql
brew services start mysql

# Безопасная настройка MySQL
mysql_secure_installation
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
sudo mysql_secure_installation
```

## 2. Создание базы данных

```bash
# Войдите в MySQL
mysql -u root -p

# Выполните команды из database_setup.sql или создайте вручную:
```

```sql
CREATE DATABASE shield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shield'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON shield.* TO 'shield'@'localhost';
FLUSH PRIVILEGES;
```

Или используйте готовый SQL скрипт:
```bash
mysql -u root -p < database_setup.sql
```

## 3. Настройка конфигурации

Отредактируйте `config.yaml`:

```yaml
database:
  host: "127.0.0.1"
  port: 3306
  username: "shield"
  password: "your_secure_password"  # ВАЖНО: Измените на свой пароль!
  database: "shield"
```

## 4. Сборка и запуск

```bash
# Установка зависимостей
go mod tidy

# Сборка
make build

# Или напрямую
go build -o build/shield ./cmd/shield

# Запуск
./run.sh
```

## 5. Тестирование API

```bash
# Регистрация нового пользователя
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123","name":"Admin User"}'

# Вход
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'

# Сохраните токен из ответа и используйте его для дальнейших запросов:
TOKEN="your_token_here"

# Создание проекта
curl -X POST http://localhost:8080/api/projects/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Minecraft Server"}'

# Добавление бэкенда
curl -X POST http://localhost:8080/api/backends/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"ip":"127.0.0.1","port":25565}'

# Получение списка проектов
curl -X GET http://localhost:8080/api/projects \
  -H "Authorization: Bearer $TOKEN"
```

## Структура проекта

```
shield/
├── cmd/shield/main.go          # Точка входа
├── internal/
│   ├── api/                    # API обработчики
│   │   ├── api.go             # Основной API
│   │   ├── auth_handlers.go   # Аутентификация
│   │   └── project_handlers.go # Управление проектами
│   ├── auth/                   # Система аутентификации
│   │   └── auth.go            # Bcrypt, токены, сессии
│   ├── database/               # Работа с MySQL
│   │   └── database.go        # CRUD операции
│   ├── config/                 # Конфигурация
│   ├── router/                 # Динамическая маршрутизация
│   ├── proxy/                  # Прокси сервер
│   └── ...
├── config.yaml                 # Конфигурация
├── database_setup.sql         # SQL для создания таблиц
└── AUTH_GUIDE.md              # Полная документация API
```

## Что реализовано

✅ **Система регистрации и авторизации:**
- Регистрация пользователей с хешированием паролей (bcrypt)
- JWT-подобные токены с временем жизни 30 дней
- Защищенные API endpoints

✅ **Управление проектами:**
- Создание проектов с уникальным Shield ID
- Привязка кастомных доменов
- CNAME валидация

✅ **Управление бэкендами:**
- Добавление/удаление бэкенд серверов
- Поддержка множественных портов
- Динамическая маршрутизация трафика

✅ **Многопортовая маршрутизация:**
- Автоматическое выделение портов из диапазонов
- Доступ через Shield ID: `id123.mangoprotect.fun`
- Доступ через кастомный домен: `mc.example.com`

✅ **База данных MySQL:**
- Пользователи, проекты, бэкенды
- Сессии с автоочисткой
- Статистика проектов

## Безопасность

- ✅ Bcrypt для хеширования паролей
- ✅ Криптографически безопасные токены
- ✅ Проверка владельца проекта перед изменениями
- ✅ Автоматическая очистка истекших сессий
- ✅ CORS настройки для API

## Troubleshooting

**MySQL не запускается:**
```bash
# macOS
brew services list
brew services restart mysql

# Linux
sudo systemctl status mysql
sudo systemctl restart mysql
```

**Ошибка подключения к БД:**
```bash
# Проверьте что пользователь создан
mysql -u shield -p

# Если нет, создайте:
mysql -u root -p
CREATE USER 'shield'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON shield.* TO 'shield'@'localhost';
```

**HAProxy ошибка permission denied:**
```bash
# Измените путь в config.yaml на локальную папку:
mkdir -p haproxy
# И в config.yaml:
# haproxy_config_path: "./haproxy/haproxy_dynamic.cfg"
```

## Следующие шаги

1. Настройте MySQL и создайте базу данных
2. Обновите пароль в config.yaml
3. Соберите и запустите проект
4. Протестируйте API регистрации/авторизации
5. Создайте проект и добавьте бэкенд
6. Настройте DNS для кастомного домена (опционально)

## Полная документация

Смотрите **AUTH_GUIDE.md** для:
- Подробного описания всех API endpoints
- Примеров использования с curl и JavaScript
- Архитектуры системы
- Настройки кастомных доменов

