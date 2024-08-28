UPDATE db_version SET status='old' WHERE status='current' and version='2.8.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 12,'2.9.0','Role based password authentication',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 12);
