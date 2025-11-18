package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"shield/internal/database"
)

type Auth struct {
	db *database.Database
}

func New(db *database.Database) *Auth {
	return &Auth{
		db: db,
	}
}

// HashPassword хеширует пароль с использованием bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword проверяет соответствие пароля хешу
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken генерирует случайный токен для сессии
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Register регистрирует нового пользователя
func (a *Auth) Register(email, password, name string) (*database.User, error) {
	// Проверка существования пользователя
	existingUser, err := a.db.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}
	if existingUser != nil {
		return nil, fmt.Errorf("user with this email already exists")
	}

	// Хеширование пароля
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Создание пользователя
	user, err := a.db.CreateUser(email, hashedPassword, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Login выполняет аутентификацию пользователя
func (a *Auth) Login(email, password string) (string, *database.User, error) {
	// Получение пользователя
	user, err := a.db.GetUserByEmail(email)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return "", nil, fmt.Errorf("invalid credentials")
	}

	// Проверка пароля
	if !CheckPassword(password, user.Password) {
		return "", nil, fmt.Errorf("invalid credentials")
	}

	// Генерация токена
	token, err := GenerateToken()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Создание сессии (действительна 30 дней)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := a.db.CreateSession(user.ID, token, expiresAt); err != nil {
		return "", nil, fmt.Errorf("failed to create session: %w", err)
	}

	return token, user, nil
}

// Logout выполняет выход из системы
func (a *Auth) Logout(token string) error {
	return a.db.DeleteSession(token)
}

// ValidateToken проверяет токен и возвращает пользователя
func (a *Auth) ValidateToken(token string) (*database.User, error) {
	// Получение сессии
	session, err := a.db.GetSessionByToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	// Получение пользователя
	user, err := a.db.GetUserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// CleanupExpiredSessions очищает истекшие сессии
func (a *Auth) CleanupExpiredSessions() error {
	return a.db.CleanupExpiredSessions()
}
