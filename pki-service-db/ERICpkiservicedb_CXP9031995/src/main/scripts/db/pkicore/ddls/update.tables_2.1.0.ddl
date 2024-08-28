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
SELECT add_column_if_not_exists('certificate_authority', 'publish_to_cdps', 'ALTER TABLE IF EXISTS certificate_authority ADD COLUMN publish_to_cdps boolean NOT NULL DEFAULT false');