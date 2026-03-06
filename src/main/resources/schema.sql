CREATE TABLE oauth2_registered_client
(
    id                            varchar(100)                            NOT NULL,
    client_id                     varchar(100)                            NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT NULL,
    client_name                   varchar(200)                            NOT NULL,
    client_authentication_methods varchar(1000)                           NOT NULL,
    authorization_grant_types     varchar(1000)                           NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)                           NOT NULL,
    client_settings               varchar(2000)                           NOT NULL,
    token_settings                varchar(2000)                           NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    blob          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      blob          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   blob          DEFAULT NULL,
    access_token_value            blob          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         blob          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           blob          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        blob          DEFAULT NULL,
    refresh_token_value           blob          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        blob          DEFAULT NULL,
    user_code_value               blob          DEFAULT NULL,
    user_code_issued_at           timestamp     DEFAULT NULL,
    user_code_expires_at          timestamp     DEFAULT NULL,
    user_code_metadata            blob          DEFAULT NULL,
    device_code_value             blob          DEFAULT NULL,
    device_code_issued_at         timestamp     DEFAULT NULL,
    device_code_expires_at        timestamp     DEFAULT NULL,
    device_code_metadata          blob          DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE IF NOT EXISTS auth_registered_client
(
    id                        varchar(100)                            NOT NULL,
    client_id                 varchar(100)                            NOT NULL,
    client_name               varchar(200)                            NOT NULL,
    scopes                    varchar(1000)                           NOT NULL,
    access_token_ttl_seconds  int           DEFAULT 600               NOT NULL,
    refresh_token_ttl_seconds int           DEFAULT 1209600           NOT NULL,
    require_consent           tinyint(1)    DEFAULT 0                 NOT NULL,
    enabled                   tinyint(1)    DEFAULT 1                 NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_auth_registered_client_client_id (client_id)
);

CREATE TABLE IF NOT EXISTS auth_authorization
(
    id                       varchar(100)                            NOT NULL,
    registered_client_id     varchar(100)                            NOT NULL,
    principal_name           varchar(200)                            NOT NULL,
    authorization_grant_type varchar(100)                            NOT NULL,
    authorized_scopes        varchar(1000) DEFAULT NULL,
    attributes               blob          DEFAULT NULL,
    access_token_hash        char(64)                                NOT NULL,
    access_token_value       blob                                    NOT NULL,
    access_token_issued_at   timestamp                               NOT NULL,
    access_token_expires_at  timestamp                               NOT NULL,
    refresh_token_hash       char(64)                                NOT NULL,
    refresh_token_value      blob                                    NOT NULL,
    refresh_token_issued_at  timestamp                               NOT NULL,
    refresh_token_expires_at timestamp                               NOT NULL,
    invalidated              tinyint(1)    DEFAULT 0                 NOT NULL,
    invalidated_at           timestamp     DEFAULT NULL,
    invalidation_reason      varchar(255)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_auth_authorization_access_token_hash (access_token_hash),
    UNIQUE KEY uk_auth_authorization_refresh_token_hash (refresh_token_hash),
    KEY idx_auth_authorization_principal_name (principal_name),
    KEY idx_auth_authorization_client_principal (registered_client_id, principal_name),
    CONSTRAINT fk_auth_authorization_registered_client
        FOREIGN KEY (registered_client_id) REFERENCES auth_registered_client (id)
);

CREATE TABLE IF NOT EXISTS auth_authorization_consent
(
    registered_client_id varchar(100)                            NOT NULL,
    principal_name       varchar(200)                            NOT NULL,
    authorities          varchar(1000)                           NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name),
    CONSTRAINT fk_auth_authorization_consent_registered_client
        FOREIGN KEY (registered_client_id) REFERENCES auth_registered_client (id)
);
