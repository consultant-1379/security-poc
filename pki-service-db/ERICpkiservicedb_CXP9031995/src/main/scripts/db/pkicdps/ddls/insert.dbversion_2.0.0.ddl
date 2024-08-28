UPDATE db_version SET status='old' WHERE status='current' and version='1.0.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 2,'2.0.0','Revoked super user permissions and altered table owners to database group',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 2);
