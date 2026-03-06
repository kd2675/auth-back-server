-- Auth domain DDL
-- Tables: user, refresh_tokens, auth_registered_client, auth_authorization, auth_authorization_consent
-- Note: OAuth2 Authorization Server tables(oauth2_*) are managed in src/main/resources/schema.sql

use AUTH;

CREATE TABLE IF NOT EXISTS user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_key VARCHAR(64) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NULL,
    email VARCHAR(255) NULL,
    user_role VARCHAR(255) NULL,
    image_url VARCHAR(255) NULL,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NULL,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    CONSTRAINT uk_user_user_key UNIQUE (user_key),
    CONSTRAINT uk_user_username UNIQUE (username),
    CONSTRAINT uk_user_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_key VARCHAR(64) NOT NULL,
    token VARCHAR(500) NOT NULL,
    expiry_date DATETIME NOT NULL,
    created_at DATETIME NULL,
    CONSTRAINT uk_refresh_tokens_user_key UNIQUE (user_key),
    CONSTRAINT uk_refresh_tokens_token UNIQUE (token),
    CONSTRAINT fk_refresh_tokens_user_key
        FOREIGN KEY (user_key) REFERENCES user(user_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_registered_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL,
    client_name VARCHAR(200) NOT NULL,
    scopes VARCHAR(1000) NOT NULL,
    access_token_ttl_seconds INT NOT NULL DEFAULT 600,
    refresh_token_ttl_seconds INT NOT NULL DEFAULT 1209600,
    require_consent TINYINT(1) NOT NULL DEFAULT 0,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    CONSTRAINT uk_auth_registered_client_client_id UNIQUE (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_authorization (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes VARCHAR(1000) NULL,
    attributes BLOB NULL,
    access_token_hash CHAR(64) NOT NULL,
    access_token_value BLOB NOT NULL,
    access_token_issued_at DATETIME NOT NULL,
    access_token_expires_at DATETIME NOT NULL,
    refresh_token_hash CHAR(64) NOT NULL,
    refresh_token_value BLOB NOT NULL,
    refresh_token_issued_at DATETIME NOT NULL,
    refresh_token_expires_at DATETIME NOT NULL,
    invalidated TINYINT(1) NOT NULL DEFAULT 0,
    invalidated_at DATETIME NULL,
    invalidation_reason VARCHAR(255) NULL,
    CONSTRAINT uk_auth_authorization_access_token_hash UNIQUE (access_token_hash),
    CONSTRAINT uk_auth_authorization_refresh_token_hash UNIQUE (refresh_token_hash),
    KEY idx_auth_authorization_principal_name (principal_name),
    KEY idx_auth_authorization_client_principal (registered_client_id, principal_name),
    CONSTRAINT fk_auth_authorization_registered_client
        FOREIGN KEY (registered_client_id) REFERENCES auth_registered_client(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_authorization_consent (
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorities VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name),
    CONSTRAINT fk_auth_authorization_consent_registered_client
        FOREIGN KEY (registered_client_id) REFERENCES auth_registered_client(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
