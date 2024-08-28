UPDATE db_version SET status='old' WHERE status='current' and version='1.1.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 3,'1.2.0','changed the access of symmetric_key table to only a secured user',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 3);

