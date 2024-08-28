UPDATE db_version SET status='old' WHERE status='current' and version='2.14.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 18,'2.15.0','Role based password authentication when making a connection in pkimanagerdb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 18);
