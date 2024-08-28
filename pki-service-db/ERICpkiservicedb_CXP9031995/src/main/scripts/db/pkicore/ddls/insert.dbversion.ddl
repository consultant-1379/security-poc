INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 1,'1.0.0','updated to new database model',CURRENT_DATE,'old' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 1);
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 2,'1.1.0','updated according to kaps database changes',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 2);

