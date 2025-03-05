CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users
ADD COLUMN IF NOT EXISTS webauthn_id BYTEA UNIQUE,
ADD COLUMN IF NOT EXISTS webauthn_public_key BYTEA,
ADD COLUMN IF NOT EXISTS webauthn_sign_count INTEGER;

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_webauthn_id ON users(webauthn_id);
