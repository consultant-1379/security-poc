UPDATE db_version SET status='old' WHERE status='current' and version='2.17.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 21,'2.18.0','Add subject_unique_identifier_value value for AMOS entity in entityprofile and entity tables',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 21);
