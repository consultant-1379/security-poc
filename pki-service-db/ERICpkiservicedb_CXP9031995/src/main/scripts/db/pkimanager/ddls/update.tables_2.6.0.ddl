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

SELECT add_column_if_not_exists('certificate_generation_info', 'for_external_ca', 'ALTER TABLE IF EXISTS certificate_generation_info ADD COLUMN for_external_ca boolean DEFAULT false');
SELECT add_column_if_not_exists('caentity', 'is_issuer_external_ca', 'ALTER TABLE IF EXISTS caentity ADD COLUMN is_issuer_external_ca  boolean DEFAULT false');
