UPDATE db_version SET status='old' WHERE status='current' and version='2.3.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 7,'2.4.0','Revoked super user permissions',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 7);
