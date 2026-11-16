-- schema.sql - the app also creates/migrates these tables automatically on startup.
-- Recommended: run the app as a dedicated least-privilege MySQL user, e.g.
--   CREATE USER 'chat_app'@'localhost' IDENTIFIED BY '<strong password>';
--   GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON secureee.* TO 'chat_app'@'localhost';

CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(32)  NOT NULL UNIQUE,
    password        VARCHAR(255) NOT NULL,            -- bcrypt hash
    role            VARCHAR(20)  NOT NULL DEFAULT 'soldier',
    otp_secret      VARCHAR(255) NOT NULL,            -- AES-256-GCM sealed TOTP secret
    totp_confirmed  TINYINT(1)   NOT NULL DEFAULT 0,
    last_otp_step   BIGINT       NOT NULL DEFAULT 0,  -- prevents OTP replay
    failed_attempts INT          NOT NULL DEFAULT 0,
    locked_until    DATETIME     NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME     NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,   -- set while a temporary password is in use
    password_expires DATETIME    NULL,                 -- temporary passwords expire
    created_by      VARCHAR(32)  NULL,
    deleted_at      DATETIME     NULL                  -- deactivated accounts keep their row for auditing
);

CREATE TABLE IF NOT EXISTS messages (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    conversation VARCHAR(80) NOT NULL DEFAULT 'ch:general',  -- 'ch:<channel>' or 'dm:<userA>|<userB>'
    sender       VARCHAR(32) NOT NULL,
    sender_role  VARCHAR(20) NOT NULL,
    recipient    VARCHAR(32) NULL,                  -- set for direct messages
    body         TEXT        NOT NULL,              -- AES-256-GCM sealed message text
    created_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_messages_conversation (conversation, id),
    INDEX idx_messages_recipient (recipient)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    event      VARCHAR(40)  NOT NULL,
    username   VARCHAR(64)  NULL,
    ip         VARCHAR(45)  NULL,
    detail     VARCHAR(512) NULL,                 -- AES-256-GCM sealed
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prev_hash  CHAR(64)     NULL,                 -- hash chain: makes edits/deletions detectable
    row_hash   CHAR(64)     NULL,
    INDEX idx_audit_created (created_at)
);
