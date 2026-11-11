-- Solo si ya tienes la base creada (create_all no altera tablas existentes).
-- Alternativa en desarrollo: docker compose down -v  y volver a levantar.
BEGIN;
ALTER TABLE users ALTER COLUMN totp_secret TYPE VARCHAR(255);
UPDATE users SET totp_secret = NULL, totp_enabled = FALSE;  -- por si hubiera secretos en claro
ALTER TABLE users
  ADD COLUMN totp_last_used_step BIGINT,
  ADD COLUMN telegram_link_token_hash VARCHAR(64) UNIQUE,
  ADD COLUMN telegram_link_expires_at TIMESTAMPTZ,
  ADD COLUMN enroll_token_hash VARCHAR(64) UNIQUE,
  ADD COLUMN enroll_expires_at TIMESTAMPTZ,
  ADD COLUMN enroll_used_at TIMESTAMPTZ,
  ADD CONSTRAINT users_telegram_chat_id_key UNIQUE (telegram_chat_id);
ALTER TABLE hosts ADD COLUMN os_version VARCHAR(100);
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_user_id_name_key;
-- falla si algun usuario ya tiene 2+ hosts: borra los sobrantes antes
ALTER TABLE hosts ADD CONSTRAINT hosts_user_id_key UNIQUE (user_id);
COMMIT;
