UPDATE db_version SET status='old' WHERE status='current' and version='2.9.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 13,'2.10.0','Replace "CN=COMUser" with "CN=<userName>" in subject_alt_name column of entity_info table in pkicoredb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 13);
