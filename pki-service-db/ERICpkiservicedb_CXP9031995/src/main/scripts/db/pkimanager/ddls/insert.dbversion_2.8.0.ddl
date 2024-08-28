UPDATE db_version SET status='old' WHERE status='current' and version='2.7.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 11,'2.8.0','Created new table ca_configuration and Added new column ca_configuration_id in caentity table',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 11);
