UPDATE db_version SET status='old' WHERE status='current' and version='2.12.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 16,'2.13.0','populated data into name_alias column lowering the values of name column of entity table in pkimanagerdb',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 16);
