CREATE OR REPLACE FUNCTION add_column_if_not_exists(table_name text, column_name text, add_column_sql text)
RETURNS void AS
$BODY$
DECLARE var_column_exists INTEGER;
BEGIN
    SELECT COUNT(A.ATTNAME) INTO VAR_COLUMN_EXISTS FROM PG_ATTRIBUTE A, PG_CLASS C
    WHERE A.ATTRELID = C.OID AND A.ATTNAME = column_name AND C.RELNAME = table_name;
 
    IF var_column_exists = 0 THEN
        execute add_column_sql;
    END IF;
END;
$BODY$
LANGUAGE plpgsql;


CREATE OR REPLACE function create_constraint_if_not_exists (
    t_name text, c_name text, constraint_sql text
) 
RETURNS void AS
$BODY$
BEGIN
    IF NOT EXISTS (SELECT constraint_name 
                   FROM information_schema.constraint_column_usage 
                   WHERE table_name = t_name  AND constraint_name = c_name) THEN
        EXECUTE constraint_sql;
    END IF;
END;
$BODY$
LANGUAGE plpgsql
;

SELECT add_column_if_not_exists('crl_generation_info', 'ca_certificate_id', 'ALTER TABLE IF EXISTS crl_generation_info ADD COLUMN ca_certificate_id bigint');

SELECT create_constraint_if_not_exists('certificate','fk_crl_generation_info_certificate','ALTER TABLE IF EXISTS crl_generation_info
	ADD CONSTRAINT fk_crl_generation_info_certificate FOREIGN KEY (ca_certificate_id)
 		REFERENCES certificate (id) MATCH SIMPLE 
 		ON UPDATE NO ACTION ON DELETE NO ACTION');
 		
 		
SELECT add_column_if_not_exists('algorithm', 'created_date', 'ALTER TABLE IF EXISTS algorithm ADD COLUMN created_date timestamp without time zone NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('algorithm', 'modified_date', 'ALTER TABLE IF EXISTS algorithm ADD COLUMN modified_date timestamp without time zone NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('externalcrlinfo', 'created_date', 'ALTER TABLE IF EXISTS externalcrlinfo ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('externalcrlinfo', 'modified_date', 'ALTER TABLE IF EXISTS externalcrlinfo ADD COLUMN modified_date timestamp without time zone NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('crlinfo', 'created_date', 'ALTER TABLE IF EXISTS crlinfo ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('crlinfo', 'modified_date', 'ALTER TABLE IF EXISTS crlinfo ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('certificateprofile', 'created_date', 'ALTER TABLE IF EXISTS certificateprofile ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('certificateprofile', 'modified_date', 'ALTER TABLE IF EXISTS certificateprofile ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('entityprofile', 'created_date', 'ALTER TABLE IF EXISTS entityprofile ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('entityprofile', 'modified_date', 'ALTER TABLE IF EXISTS entityprofile ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('trustprofile', 'created_date', 'ALTER TABLE IF EXISTS trustprofile ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('trustprofile', 'modified_date', 'ALTER TABLE IF EXISTS trustprofile ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('certificate', 'created_date', 'ALTER TABLE IF EXISTS certificate ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('certificate', 'modified_date', 'ALTER TABLE IF EXISTS certificate ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('entity', 'created_date', 'ALTER TABLE IF EXISTS entity ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('entity', 'modified_date', 'ALTER TABLE IF EXISTS entity ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');

SELECT add_column_if_not_exists('caentity', 'created_date', 'ALTER TABLE IF EXISTS caentity ADD COLUMN created_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
SELECT add_column_if_not_exists('caentity', 'modified_date', 'ALTER TABLE IF EXISTS caentity ADD COLUMN modified_date timestamp without time zone  NOT NULL DEFAULT current_timestamp');
