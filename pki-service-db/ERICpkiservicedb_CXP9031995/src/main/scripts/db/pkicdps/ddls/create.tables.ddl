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

SELECT create_sequence_if_not_exists('seq_cdps_crl_id','CREATE SEQUENCE SEQ_CDPS_CRL_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CDPS_CRL_ID OWNER TO pkicdps;

CREATE TABLE IF NOT EXISTS cdps_crl
(
  id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_CDPS_CRL_ID'),
  ca_name CHARACTER VARYING(255) NOT NULL,
  cert_serial_number CHARACTER VARYING(255) NOT NULL,
  crl BYTEA NOT NULL,
  CONSTRAINT pk_cdps_crl_id PRIMARY KEY (id),
  CONSTRAINT uk_cdps_ca_name_cert_serial_number UNIQUE (ca_name, cert_serial_number)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS cdps_crl
  OWNER TO pkicdps;