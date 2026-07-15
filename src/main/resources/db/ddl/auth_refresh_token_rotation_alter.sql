USE AUTH;

ALTER TABLE refresh_tokens
    ADD COLUMN client_id VARCHAR(100) NULL AFTER expiry_date,
    ADD COLUMN family_id VARCHAR(36) NULL AFTER client_id,
    ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' AFTER family_id,
    ADD COLUMN replaced_by_token VARCHAR(500) NULL AFTER status,
    ADD COLUMN rotated_at DATETIME NULL AFTER replaced_by_token,
    ADD COLUMN revoked_at DATETIME NULL AFTER rotated_at;

UPDATE refresh_tokens
SET client_id = 'legacy',
    family_id = UUID()
WHERE client_id IS NULL OR family_id IS NULL;

ALTER TABLE refresh_tokens
    MODIFY COLUMN client_id VARCHAR(100) NOT NULL,
    MODIFY COLUMN family_id VARCHAR(36) NOT NULL,
    DROP INDEX uk_refresh_tokens_user_key,
    ADD INDEX idx_refresh_tokens_family_status (family_id, status),
    ADD INDEX idx_refresh_tokens_user_client_status (user_key, client_id, status);
