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

SELECT create_sequence_if_not_exists('db_version_id','CREATE SEQUENCE DB_VERSION_ID START 1');
ALTER SEQUENCE IF EXISTS DB_VERSION_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS db_version
(
  id integer NOT NULL DEFAULT NEXTVAL('DB_VERSION_ID'),
  version character varying(255) NOT NULL,
  comments character varying(255) NOT NULL,
  updated_date date NOT NULL,
  status character varying(255) NOT NULL,
  CONSTRAINT pk_db_version_id PRIMARY KEY (id),
  CONSTRAINT uk_db_version_id UNIQUE (version)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS db_version
  OWNER TO pkimanager;
  