# Shield - Система регистрации и авторизации

## Быстрый старт

### 1. Установка MySQL/MariaDB

**macOS:**
```bash
brew install mysql
brew services start mysql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
```

### 2. Настройка базы данных

```bash
# Войдите в MySQL
mysql -u root -p

# Выполните SQL скрипт
source /path/to/shield/database_setup.sql

# Или напрямую:
mysql -u root -p < database_setup.sql
```

**Важно!** Измените пароль в файле `database_setup.sql` и `config.yaml` на свой собственный.

### 3. Настройка конфигурации

Отредактируйте `config.yaml`:

```yaml
database:
  host: "127.0.0.1"
  port: 3306
  username: "shield"
  password: "your_secure_password"  # Измените на свой пароль!
  database: "shield"
```

### 4. Установка зависимостей

```bash
cd /Users/vova/GolandProjects/shield
go mod tidy
```

### 5. Запуск приложения

```bash
make build
./run.sh
```

Или напрямую:

```bash
go build -o build/shield ./cmd/shield
./build/shield
```

## API Endpoints

### Аутентификация

#### Регистрация
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "John Doe"
}
```

**Ответ:**
```json
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "id": 1,
    "email": "user@example.com",
    "name": "John Doe",
    "plan": "free"
  }
}
```

#### Вход
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Ответ:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "a1b2c3d4e5f6...",
    "user": {
      "id": 1,
      "email": "user@example.com",
      "name": "John Doe",
      "plan": "free"
    }
  }
}
```

**Важно:** Сохраните токен! Используйте его в заголовке `Authorization: Bearer <token>` для всех последующих запросов.

#### Получение информации о пользователе
```bash
GET /api/auth/me
Authorization: Bearer <your_token>
```

#### Выход
```bash
POST /api/auth/logout
Authorization: Bearer <your_token>
```

### Проекты

#### Получить список проектов
```bash
GET /api/projects
Authorization: Bearer <your_token>
```

#### Создать проект
```bash
POST /api/projects/create
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "name": "My Minecraft Server"
}
```

**Ответ:**
```json
{
  "success": true,
  "message": "Project created successfully",
  "data": {
    "id": 1,
    "name": "My Minecraft Server",
    "shield_id": "a1b2c3d4e5f6a7b8",
    "domain": "",
    "status": "pending",
    "created_at": "2025-11-18T12:00:00Z"
  }
}
```

#### Обновить домен проекта
```bash
POST /api/projects/update-domain
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "project_id": 1,
  "domain": "mc.example.com"
}
```

#### Проверить CNAME запись домена
```bash
POST /api/projects/validate-domain
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "project_id": 1
}
```

### Бэкенды

#### Добавить бэкенд к проекту
```bash
POST /api/backends/add
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "project_id": 1,
  "ip": "10.0.0.5",
  "port": 25565
}
```

**Ответ:**
```json
{
  "success": true,
  "message": "Backend added successfully",
  "data": {
    "id": 1,
    "project_id": 1,
    "ip": "10.0.0.5",
    "port": 25565,
    "status": "active",
    "created_at": "2025-11-18T12:00:00Z"
  }
}
```

#### Удалить бэкенд
```bash
POST /api/backends/remove
Authorization: Bearer <your_token>
Content-Type: application/json

{
  "backend_id": 1
}
```

## Примеры использования

### С помощью curl

```bash
# 1. Регистрация
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test User"}'

# 2. Вход
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}' \
  | jq -r '.data.token')

# 3. Создание проекта
curl -X POST http://localhost:8080/api/projects/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Server"}'

# 4. Добавление бэкенда
curl -X POST http://localhost:8080/api/backends/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_id":1,"ip":"127.0.0.1","port":25565}'

# 5. Получение списка проектов
curl -X GET http://localhost:8080/api/projects \
  -H "Authorization: Bearer $TOKEN"
```

### С помощью JavaScript (fetch)

```javascript
// Регистрация
async function register() {
  const response = await fetch('http://localhost:8080/api/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'test123',
      name: 'Test User'
    })
  });
  const data = await response.json();
  console.log(data);
}

// Вход
async function login() {
  const response = await fetch('http://localhost:8080/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'test123'
    })
  });
  const data = await response.json();
  const token = data.data.token;
  localStorage.setItem('token', token);
  return token;
}

// Получение проектов
async function getProjects() {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8080/api/projects', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  const data = await response.json();
  console.log(data);
}

// Создание проекта
async function createProject(name) {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8080/api/projects/create', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name })
  });
  const data = await response.json();
  console.log(data);
}
```

## Архитектура системы

### Многопортовая маршрутизация

Система поддерживает динамическое распределение портов для каждого проекта:

1. **Создание проекта** - генерируется уникальный Shield ID (например: `a1b2c3d4e5f6a7b8`)
2. **Добавление бэкенда** - система автоматически выделяет порт из настроенных диапазонов
3. **Доступ к серверу:**
   - Через выделенный порт: `connect.mangoprotect.fun:25601`
   - Через Shield ID: `a1b2c3d4e5f6a7b8.mangoprotect.fun`
   - Через кастомный домен: `mc.example.com` (после настройки CNAME)

### Настройка кастомного домена

1. Создайте CNAME запись для вашего домена:
   ```
   mc.example.com -> a1b2c3d4e5f6a7b8.mangoprotect.fun
   ```

2. Обновите домен проекта через API:
   ```bash
   POST /api/projects/update-domain
   {
     "project_id": 1,
     "domain": "mc.example.com"
   }
   ```

3. Проверьте CNAME запись:
   ```bash
   POST /api/projects/validate-domain
   {
     "project_id": 1
   }
   ```

## Безопасность

- Пароли хешируются с использованием bcrypt
- Сессии хранятся в базе данных с временем истечения (30 дней)
- Токены генерируются криптографически безопасным способом
- Все эндпоинты проектов и бэкендов требуют аутентификации
- Автоматическая очистка истекших сессий каждый час

## Таблицы базы данных

- **users** - пользователи системы
- **projects** - проекты пользователей
- **backends** - бэкенд серверы проектов
- **sessions** - активные сессии
- **project_stats** - статистика проектов

## Troubleshooting

### Ошибка подключения к базе данных

```
Failed to initialize database: failed to ping database
```

**Решение:**
1. Проверьте что MySQL запущен: `mysql.server status` или `systemctl status mysql`
2. Проверьте настройки в `config.yaml`
3. Проверьте что пользователь и база данных созданы: `mysql -u shield -p`

### Permission denied для /etc/haproxy

```
permission denied: open /etc/haproxy/haproxy_dynamic.cfg
```

**Решение:**
1. Измените путь в `config.yaml`:
   ```yaml
   router:
     haproxy_config_path: "./haproxy/haproxy_dynamic.cfg"
   ```
2. Создайте папку: `mkdir -p haproxy`

## Дополнительная информация

- Веб-панель: http://localhost:8080
- API документация: http://localhost:8080/api
- Логи: смотрите в консоли или файле логов (если настроено в config.yaml)

## Лицензия

Shield Protection System © 2025

