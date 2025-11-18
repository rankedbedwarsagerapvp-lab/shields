package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"shield/internal/database"
	"shield/internal/logger"
)

// generateShieldID генерирует уникальный ID для проекта
func generateShieldID() string {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// handleProjects возвращает список проектов пользователя
func (a *API) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем пользователя
	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Получаем проекты пользователя
	projects, err := a.db.GetUserProjects(user.ID)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get user projects")
		a.sendError(w, "Failed to get projects", http.StatusInternalServerError)
		return
	}

	// Добавляем информацию о бэкендах для каждого проекта
	projectsWithBackends := make([]map[string]interface{}, 0, len(projects))
	for _, project := range projects {
		backends, err := a.db.GetProjectBackends(project.ID)
		if err != nil {
			logger.Log.WithError(err).Error("Failed to get project backends")
			backends = []database.Backend{}
		}

		// Получаем статистику проекта
		a.projectMutex.RLock()
		stats, hasStats := a.projectStats[project.ShieldID]
		a.projectMutex.RUnlock()

		projectData := map[string]interface{}{
			"id":         project.ID,
			"name":       project.Name,
			"shield_id":  project.ShieldID,
			"domain":     project.Domain,
			"status":     project.Status,
			"backends":   backends,
			"created_at": project.CreatedAt,
			"updated_at": project.UpdatedAt,
		}

		if hasStats {
			projectData["stats"] = stats
		}

		projectsWithBackends = append(projectsWithBackends, projectData)
	}

	a.sendJSON(w, Response{
		Success: true,
		Data:    projectsWithBackends,
	})
}

// handleCreateProject создает новый проект
func (a *API) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		a.sendError(w, "Project name is required", http.StatusBadRequest)
		return
	}

	// Генерируем уникальный Shield ID
	shieldID := generateShieldID()

	// Создаем проект
	project, err := a.db.CreateProject(user.ID, req.Name, shieldID)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to create project")
		a.sendError(w, "Failed to create project", http.StatusInternalServerError)
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"user_id":    user.ID,
		"project_id": project.ID,
		"shield_id":  project.ShieldID,
	}).Info("Project created")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Project created successfully",
		Data: map[string]interface{}{
			"id":         project.ID,
			"name":       project.Name,
			"shield_id":  project.ShieldID,
			"domain":     project.Domain,
			"status":     project.Status,
			"created_at": project.CreatedAt,
		},
	})
}

// handleUpdateProjectDomain обновляет домен проекта
func (a *API) handleUpdateProjectDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ProjectID int    `json:"project_id"`
		Domain    string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Проверяем что проект принадлежит пользователю
	project, err := a.db.GetProjectByID(req.ProjectID)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get project")
		a.sendError(w, "Failed to get project", http.StatusInternalServerError)
		return
	}

	if project == nil {
		a.sendError(w, "Project not found", http.StatusNotFound)
		return
	}

	if project.UserID != user.ID {
		a.sendError(w, "Access denied", http.StatusForbidden)
		return
	}

	// Обновляем домен
	if err := a.db.UpdateProjectDomain(req.ProjectID, req.Domain, "validating"); err != nil {
		logger.Log.WithError(err).Error("Failed to update project domain")
		a.sendError(w, "Failed to update domain", http.StatusInternalServerError)
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"project_id": req.ProjectID,
		"domain":     req.Domain,
	}).Info("Project domain updated")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Domain updated successfully",
	})
}

// handleValidateDomainCNAME проверяет CNAME записи домена
func (a *API) handleValidateDomainCNAME(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ProjectID int `json:"project_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Проверяем что проект принадлежит пользователю
	project, err := a.db.GetProjectByID(req.ProjectID)
	if err != nil || project == nil || project.UserID != user.ID {
		a.sendError(w, "Project not found", http.StatusNotFound)
		return
	}

	// Проверяем CNAME
	valid, reason := a.validateDomain(project.Domain)

	// Обновляем статус проекта
	newStatus := "error"
	if valid {
		newStatus = "active"
	}

	if err := a.db.UpdateProjectStatus(req.ProjectID, newStatus); err != nil {
		logger.Log.WithError(err).Error("Failed to update project status")
	}

	a.sendJSON(w, Response{
		Success: valid,
		Message: reason,
		Data: map[string]interface{}{
			"domain": project.Domain,
			"valid":  valid,
			"status": newStatus,
		},
	})
}

// handleProjectStats возвращает статистику проекта
func (a *API) handleProjectStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	projectIDStr := r.URL.Query().Get("project_id")
	projectID, err := strconv.Atoi(projectIDStr)
	if err != nil {
		a.sendError(w, "Invalid project_id", http.StatusBadRequest)
		return
	}

	// Проверяем что проект принадлежит пользователю
	project, err := a.db.GetProjectByID(projectID)
	if err != nil || project == nil || project.UserID != user.ID {
		a.sendError(w, "Project not found", http.StatusNotFound)
		return
	}

	// Получаем статистику
	a.projectMutex.RLock()
	stats, hasStats := a.projectStats[project.ShieldID]
	a.projectMutex.RUnlock()

	if !hasStats {
		stats = &ProjectStats{
			BytesTransferred: 0,
			PacketsPerSecond: 0,
			ConnectionsTotal: 0,
			ActivePlayers:    0,
			TrafficHistory:   []TrafficPoint{},
		}
	}

	a.sendJSON(w, Response{
		Success: true,
		Data:    stats,
	})
}

// handleAddBackend добавляет бэкенд к проекту
func (a *API) handleAddBackend(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ProjectID int    `json:"project_id"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Валидация
	if req.IP == "" || req.Port <= 0 || req.Port > 65535 {
		a.sendError(w, "Invalid IP or port", http.StatusBadRequest)
		return
	}

	// Проверяем что проект принадлежит пользователю
	project, err := a.db.GetProjectByID(req.ProjectID)
	if err != nil || project == nil || project.UserID != user.ID {
		a.sendError(w, "Project not found", http.StatusNotFound)
		return
	}

	// Создаем бэкенд
	backend, err := a.db.CreateBackend(req.ProjectID, req.IP, req.Port)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to create backend")
		a.sendError(w, "Failed to create backend", http.StatusInternalServerError)
		return
	}

	// Если есть роутер, добавляем маршрут
	if a.router != nil {
		domain := project.ShieldID + ".mangoprotect.fun"
		if project.Domain != "" {
			domain = project.Domain
		}

		route, err := a.router.AddRoute(
			project.ShieldID,
			domain,
			req.IP,
			req.Port,
		)
		if err != nil {
			logger.Log.WithError(err).Error("Failed to add route")
		} else {
			logger.Log.WithFields(map[string]interface{}{
				"domain":       domain,
				"backend_ip":   req.IP,
				"backend_port": req.Port,
				"proxy_port":   route.ProxyPort,
			}).Info("Route added")
		}
	}

	logger.Log.WithFields(map[string]interface{}{
		"project_id":   req.ProjectID,
		"backend_id":   backend.ID,
		"backend_ip":   backend.IP,
		"backend_port": backend.Port,
	}).Info("Backend added")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Backend added successfully",
		Data:    backend,
	})
}

// handleRemoveBackend удаляет бэкенд
func (a *API) handleRemoveBackend(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req struct {
		BackendID int `json:"backend_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Получаем бэкенд
	backend, err := a.db.GetBackendByID(req.BackendID)
	if err != nil || backend == nil {
		a.sendError(w, "Backend not found", http.StatusNotFound)
		return
	}

	// Проверяем что проект принадлежит пользователю
	project, err := a.db.GetProjectByID(backend.ProjectID)
	if err != nil || project == nil || project.UserID != user.ID {
		a.sendError(w, "Access denied", http.StatusForbidden)
		return
	}

	// Если есть роутер, удаляем маршрут
	if a.router != nil {
		routes := a.router.GetRoutesByShieldID(project.ShieldID)
		for _, route := range routes {
			if route.BackendIP == backend.IP && route.BackendPort == backend.Port {
				if err := a.router.RemoveRoute(route.Domain); err != nil {
					logger.Log.WithError(err).Error("Failed to remove route")
				} else {
					logger.Log.WithFields(map[string]interface{}{
						"domain":     route.Domain,
						"proxy_port": route.ProxyPort,
					}).Info("Route removed")
				}
			}
		}
	}

	// Удаляем бэкенд
	if err := a.db.DeleteBackend(req.BackendID); err != nil {
		logger.Log.WithError(err).Error("Failed to delete backend")
		a.sendError(w, "Failed to delete backend", http.StatusInternalServerError)
		return
	}

	logger.Log.WithField("backend_id", req.BackendID).Info("Backend removed")

	a.sendJSON(w, Response{
		Success: true,
		Message: "Backend removed successfully",
	})
}

// getUserFromRequest извлекает пользователя из запроса
func (a *API) getUserFromRequest(r *http.Request) (*database.User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header")
	}

	token := parts[1]
	user, err := a.auth.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	return user, nil
}
