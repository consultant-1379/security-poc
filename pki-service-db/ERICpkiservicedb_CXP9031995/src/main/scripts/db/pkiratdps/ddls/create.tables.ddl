CREATE OR REPLACE function create_sequence_if_not_exists (
    s_name text, sequence_sql text
)
RETURNS void AS
$BODY$
BEGIN
    IF NOT EXISTS (SELECT 0
                   FROM pg_class WHERE relname = s_name) THEN
        EXECUTE sequence_sql;
    END IF;
END;
$BODY$
LANGUAGE plpgsql
;

SELECT create_sequence_if_not_exists('seq_tdps_id_generator','CREATE SEQUENCE SEQ_TDPS_ID_GENERATOR START 1');
ALTER SEQUENCE IF EXISTS SEQ_TDPS_ID_GENERATOR OWNER TO pkiratdps;

CREATE TABLE IF NOT EXISTS tdpsdata
(
  id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_TDPS_ID_GENERATOR'),
  certificate BYTEA NOT NULL,
  entity_name CHARACTER VARYING(255) NOT NULL,
  entity_type CHARACTER VARYING(255) NOT NULL,
  serial_no CHARACTER VARYING(255) NOT NULL,
  issuer_name CHARACTER VARYING(255) NOT NULL,
  status CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_tdpsdata_id PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS tdpsdata
  OWNER TO pkiratdps;