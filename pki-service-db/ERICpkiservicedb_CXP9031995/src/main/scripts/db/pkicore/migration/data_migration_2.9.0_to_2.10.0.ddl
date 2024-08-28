-- update entity_info table
CREATE EXTENSION IF NOT EXISTS dblink;

UPDATE entity_info set subject_alt_name=REPLACE(subject_alt_name, 'CN=COMUser', CONCAT('CN=',name)) where name in (SELECT * FROM dblink('dbname=pkimanagerdb', 'SELECT name FROM entity WHERE entity_category_id = (SELECT id FROM entity_category WHERE name =''USER-SLS'')') as t1 (a varchar(255)) ) and subject_alt_name LIKE '%CN=COMUser%';

DROP EXTENSION IF EXISTS dblink;
