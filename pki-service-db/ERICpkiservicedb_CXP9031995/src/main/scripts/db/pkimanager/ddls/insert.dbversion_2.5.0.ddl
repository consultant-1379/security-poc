UPDATE db_version SET status='old' WHERE status='current' and version='2.4.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 8,'2.5.0','New Algorithm ECDSA_521 added to alogorithm table',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 8);
