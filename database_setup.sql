-- Shield Protection System Database Setup
-- MySQL/MariaDB

-- Create database
CREATE DATABASE IF NOT EXISTS shield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (замените 'shield_password' на свой пароль)
CREATE USER IF NOT EXISTS 'shield'@'localhost' IDENTIFIED BY 'shield_password';
GRANT ALL PRIVILEGES ON shield.* TO 'shield'@'localhost';
FLUSH PRIVILEGES;

USE shield;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) DEFAULT 'free',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backends table
CREATE TABLE IF NOT EXISTS backends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    ip VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    INDEX idx_project_id (project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Project statistics table
CREATE TABLE IF NOT EXISTS project_stats (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Создание процедуры для очистки старых сессий
DELIMITER $$
CREATE EVENT IF NOT EXISTS cleanup_expired_sessions
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END$$
DELIMITER ;

-- Создание процедуры для очистки старой статистики (старше 7 дней)
DELIMITER $$
CREATE EVENT IF NOT EXISTS cleanup_old_stats
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM project_stats WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 7 DAY);
END$$
DELIMITER ;

-- Включаем планировщик событий
SET GLOBAL event_scheduler = ON;

SELECT 'Database setup completed successfully!' AS message;

