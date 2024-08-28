UPDATE db_version SET status='old' WHERE status='current' and version='2.10.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 14,'2.11.0','Added new table entity_subject_dn_hash to store the id and hash of reordered subject_dn from entity table in pkimanagerdb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 14);

