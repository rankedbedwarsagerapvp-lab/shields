package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"shield/internal/logger"
)

type Database struct {
	db *sql.DB
}

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Project struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Name      string    `json:"name"`
	ShieldID  string    `json:"shield_id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"` // "pending", "validating", "active", "error"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Backend struct {
	ID        int       `json:"id"`
	ProjectID int       `json:"project_id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Status    string    `json:"status"` // "active", "inactive"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func New(host string, port int, username, password, database string) (*Database, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
		username, password, host, port, database)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	logger.Log.Info("Database connection established")

	d := &Database{db: db}

	// Initialize tables
	if err := d.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return d, nil
}

func (d *Database) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			plan VARCHAR(50) DEFAULT 'free',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_email (email)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		`CREATE TABLE IF NOT EXISTS projects (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			name VARCHAR(255) NOT NULL,
			shield_id VARCHAR(255) UNIQUE NOT NULL,
			domain VARCHAR(255) DEFAULT '',
			status VARCHAR(50) DEFAULT 'pending',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id),
			INDEX idx_shield_id (shield_id),
			INDEX idx_domain (domain)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		`CREATE TABLE IF NOT EXISTS backends (
			id INT AUTO_INCREMENT PRIMARY KEY,
			project_id INT NOT NULL,
			ip VARCHAR(45) NOT NULL,
			port INT NOT NULL,
			status VARCHAR(50) DEFAULT 'active',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
			INDEX idx_project_id (project_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_token (token),
			INDEX idx_user_id (user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		`CREATE TABLE IF NOT EXISTS project_stats (
			id INT AUTO_INCREMENT PRIMARY KEY,
			project_id INT NOT NULL,
			bytes_transferred BIGINT DEFAULT 0,
			packets_per_second FLOAT DEFAULT 0,
			connections_total BIGINT DEFAULT 0,
			active_players INT DEFAULT 0,
			recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
			INDEX idx_project_id (project_id),
			INDEX idx_recorded_at (recorded_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	logger.Log.Info("Database tables initialized")
	return nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

// User operations
func (d *Database) CreateUser(email, password, name string) (*User, error) {
	result, err := d.db.Exec(
		"INSERT INTO users (email, password, name, plan) VALUES (?, ?, ?, ?)",
		email, password, name, "free",
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return d.GetUserByID(int(id))
}

func (d *Database) GetUserByEmail(email string) (*User, error) {
	user := &User{}
	err := d.db.QueryRow(
		"SELECT id, email, password, name, plan, created_at, updated_at FROM users WHERE email = ?",
		email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.Name, &user.Plan, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *Database) GetUserByID(id int) (*User, error) {
	user := &User{}
	err := d.db.QueryRow(
		"SELECT id, email, password, name, plan, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Email, &user.Password, &user.Name, &user.Plan, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Session operations
func (d *Database) CreateSession(userID int, token string, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
		userID, token, expiresAt,
	)
	return err
}

func (d *Database) GetSessionByToken(token string) (*Session, error) {
	session := &Session{}
	err := d.db.QueryRow(
		"SELECT id, user_id, token, expires_at, created_at FROM sessions WHERE token = ? AND expires_at > NOW()",
		token,
	).Scan(&session.ID, &session.UserID, &session.Token, &session.ExpiresAt, &session.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (d *Database) DeleteSession(token string) error {
	_, err := d.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (d *Database) CleanupExpiredSessions() error {
	_, err := d.db.Exec("DELETE FROM sessions WHERE expires_at < NOW()")
	return err
}

// Project operations
func (d *Database) CreateProject(userID int, name, shieldID string) (*Project, error) {
	result, err := d.db.Exec(
		"INSERT INTO projects (user_id, name, shield_id, status) VALUES (?, ?, ?, ?)",
		userID, name, shieldID, "pending",
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return d.GetProjectByID(int(id))
}

func (d *Database) GetProjectByID(id int) (*Project, error) {
	project := &Project{}
	err := d.db.QueryRow(
		"SELECT id, user_id, name, shield_id, domain, status, created_at, updated_at FROM projects WHERE id = ?",
		id,
	).Scan(&project.ID, &project.UserID, &project.Name, &project.ShieldID, &project.Domain, &project.Status, &project.CreatedAt, &project.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return project, nil
}

func (d *Database) GetProjectByShieldID(shieldID string) (*Project, error) {
	project := &Project{}
	err := d.db.QueryRow(
		"SELECT id, user_id, name, shield_id, domain, status, created_at, updated_at FROM projects WHERE shield_id = ?",
		shieldID,
	).Scan(&project.ID, &project.UserID, &project.Name, &project.ShieldID, &project.Domain, &project.Status, &project.CreatedAt, &project.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return project, nil
}

func (d *Database) GetUserProjects(userID int) ([]Project, error) {
	rows, err := d.db.Query(
		"SELECT id, user_id, name, shield_id, domain, status, created_at, updated_at FROM projects WHERE user_id = ? ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.ShieldID, &p.Domain, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}

	return projects, nil
}

func (d *Database) UpdateProjectDomain(projectID int, domain, status string) error {
	_, err := d.db.Exec(
		"UPDATE projects SET domain = ?, status = ?, updated_at = NOW() WHERE id = ?",
		domain, status, projectID,
	)
	return err
}

func (d *Database) UpdateProjectStatus(projectID int, status string) error {
	_, err := d.db.Exec(
		"UPDATE projects SET status = ?, updated_at = NOW() WHERE id = ?",
		status, projectID,
	)
	return err
}

func (d *Database) DeleteProject(projectID int) error {
	_, err := d.db.Exec("DELETE FROM projects WHERE id = ?", projectID)
	return err
}

// Backend operations
func (d *Database) CreateBackend(projectID int, ip string, port int) (*Backend, error) {
	result, err := d.db.Exec(
		"INSERT INTO backends (project_id, ip, port, status) VALUES (?, ?, ?, ?)",
		projectID, ip, port, "active",
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return d.GetBackendByID(int(id))
}

func (d *Database) GetBackendByID(id int) (*Backend, error) {
	backend := &Backend{}
	err := d.db.QueryRow(
		"SELECT id, project_id, ip, port, status, created_at, updated_at FROM backends WHERE id = ?",
		id,
	).Scan(&backend.ID, &backend.ProjectID, &backend.IP, &backend.Port, &backend.Status, &backend.CreatedAt, &backend.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return backend, nil
}

func (d *Database) GetProjectBackends(projectID int) ([]Backend, error) {
	rows, err := d.db.Query(
		"SELECT id, project_id, ip, port, status, created_at, updated_at FROM backends WHERE project_id = ? ORDER BY created_at ASC",
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backends []Backend
	for rows.Next() {
		var b Backend
		if err := rows.Scan(&b.ID, &b.ProjectID, &b.IP, &b.Port, &b.Status, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		backends = append(backends, b)
	}

	return backends, nil
}

func (d *Database) DeleteBackend(backendID int) error {
	_, err := d.db.Exec("DELETE FROM backends WHERE id = ?", backendID)
	return err
}

func (d *Database) UpdateBackendStatus(backendID int, status string) error {
	_, err := d.db.Exec(
		"UPDATE backends SET status = ?, updated_at = NOW() WHERE id = ?",
		status, backendID,
	)
	return err
}
