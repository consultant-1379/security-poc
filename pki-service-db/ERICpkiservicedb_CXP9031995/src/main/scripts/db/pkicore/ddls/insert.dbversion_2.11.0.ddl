UPDATE db_version SET status='old' WHERE status='current' and version='2.10.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 14,'2.11.0','Alter the validity column of certificate_generation_info table to 15 in pkicoredb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 14);
