INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 1,'1.0.0','created new pkiracmp database',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 1);
