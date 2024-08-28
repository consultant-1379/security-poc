UPDATE db_version SET status='old' WHERE status='current' and version='2.5.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 9,'2.6.0','Added new column is_issuer_external_ca in caentity table and for_external_ca in certificate_generation_info table for External Root CA',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 9);
