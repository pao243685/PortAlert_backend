-- Detalle de alerta: reporte y proceso que la originaron, tipo de evento y huella (campos del diagrama).
BEGIN;
CREATE TYPE event_type AS ENUM ('puerto_nuevo', 'proceso_sospechoso');
ALTER TABLE alerts
  ADD COLUMN report_id INTEGER REFERENCES reports (id) ON DELETE SET NULL,
  ADD COLUMN process_id INTEGER REFERENCES processes (id) ON DELETE SET NULL,
  ADD COLUMN event_type event_type,
  ADD COLUMN fingerprint VARCHAR(64);
COMMIT;
