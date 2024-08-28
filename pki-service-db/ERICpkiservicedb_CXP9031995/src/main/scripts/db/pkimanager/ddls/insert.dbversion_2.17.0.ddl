UPDATE db_version SET status='old' WHERE status='current' and version='2.16.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 20,'2.17.0','Replace "CN=COMUser" with "CN=<userName>" in subject_alt_name column of entity table in pkimanagerdb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 20);
