UPDATE db_version SET status='old' WHERE status='current' and version='2.2.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 6,'2.3.0','Added New Colum in crl_generation_info table for certificate relation',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 6);
