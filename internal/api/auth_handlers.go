package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"shield/internal/database"
	"shield/internal/logger"
)

// Middleware для проверки аутентификации
func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.sendError(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Проверяем формат Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			a.sendError(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Валидируем токен
		user, err := a.auth.ValidateToken(token)
		if err != nil {
			a.sendError(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Сохраняем пользователя в контексте
		r.Header.Set("X-User-ID", fmt.Sprintf("%d", user.ID))
		r.Header.Set("X-User-Email", user.Email)

		next(w, r)
	}
}

// handleRegister обрабатывает регистрацию нового пользователя
func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Валидация
	if req.Email == "" || req.Password == "" || req.Name == "" {
		a.sendError(w, "Email, password and name are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		a.sendError(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	// Регистрация пользователя
	user, err := a.auth.Register(req.Email, req.Password, req.Name)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to register user")
		a.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	logger.Log.WithField("email", user.Email).Info("User registered")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Registration successful",
		Data: map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"plan":  user.Plan,
		},
	})
}

// handleLogin обрабатывает вход пользователя
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Валидация
	if req.Email == "" || req.Password == "" {
		a.sendError(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Аутентификация
	token, user, err := a.auth.Login(req.Email, req.Password)
	if err != nil {
		logger.Log.WithError(err).Warn("Failed login attempt")
		a.sendError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	logger.Log.WithField("email", user.Email).Info("User logged in")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Login successful",
		Data: map[string]interface{}{
			"token": token,
			"user": map[string]interface{}{
				"id":    user.ID,
				"email": user.Email,
				"name":  user.Name,
				"plan":  user.Plan,
			},
		},
	})
}

// handleLogout обрабатывает выход пользователя
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем токен из заголовка
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.sendJSON(w, Response{Success: true, Message: "Logged out"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		token := parts[1]
		if err := a.auth.Logout(token); err != nil {
			logger.Log.WithError(err).Error("Failed to logout")
		}
	}

	logger.Log.Info("User logged out")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Logged out successfully",
	})
}

// handleMe возвращает информацию о текущем пользователе
func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем токен из заголовка
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		a.sendError(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Валидируем токен и получаем пользователя
	user, err := a.auth.ValidateToken(token)
	if err != nil {
		a.sendError(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Получаем проекты пользователя
	projects, err := a.db.GetUserProjects(user.ID)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get user projects")
		projects = []database.Project{}
	}

	a.sendJSON(w, Response{
		Success: true,
		Data: map[string]interface{}{
			"id":       user.ID,
			"email":    user.Email,
			"name":     user.Name,
			"plan":     user.Plan,
			"projects": projects,
		},
	})
}
