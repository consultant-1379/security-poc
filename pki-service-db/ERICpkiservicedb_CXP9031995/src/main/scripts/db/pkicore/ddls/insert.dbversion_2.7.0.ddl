UPDATE db_version SET status='old' WHERE status='current' and version='2.6.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 10,'2.7.0','Adding Index for the tables crlInfo,entity_info',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 10);
