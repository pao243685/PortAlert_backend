-- Primera revisión: marcar "es normal en este equipo" (baseline) y terminar la revisión.
BEGIN;
ALTER TABLE hosts ADD COLUMN review_completed_at TIMESTAMPTZ;
CREATE TABLE baseline (
	id SERIAL NOT NULL,
	host_id INTEGER NOT NULL,
	port INTEGER NOT NULL,
	protocol VARCHAR(10) NOT NULL,
	exe_path TEXT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (host_id, port, protocol, exe_path),
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE CASCADE
);
CREATE INDEX ix_baseline_host_id ON baseline (host_id);
-- Quien ya vinculó un equipo antes de esta versión no pasa por la primera revisión.
UPDATE hosts SET review_completed_at = now() WHERE score IS NOT NULL;
COMMIT;
