-- Initialize database and essential tables for Reyonic
CREATE DATABASE IF NOT EXISTS `reyonic_mvp_dark` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `reyonic_mvp_dark`;

CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `name` VARCHAR(150) NULL,
  `role` VARCHAR(50) NOT NULL DEFAULT 'customer',
  `workspace_id` INT NOT NULL DEFAULT 0,
  `totp_secret` VARCHAR(64) NULL,
  `totp_enabled` TINYINT(1) NOT NULL DEFAULT 0,
  `last_login_at` DATETIME NULL,
  `last_login_ip` VARCHAR(64) NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `identifier` VARCHAR(190) NOT NULL,
  `ip_address` VARCHAR(64) NOT NULL,
  `attempted_at` DATETIME NOT NULL,
  `success` TINYINT(1) NOT NULL DEFAULT 0,
  INDEX `idx_identifier_time` (`identifier`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
