UPDATE db_version SET status='old' WHERE status='current' and version='2.0.0';
INSERT INTO db_version(id,version,comments,updated_date,status) SELECT 4,'2.1.0','Added boolean flag for tdps acknowledgement in Certificate table',CURRENT_DATE,'current' WHERE NOT EXISTS (SELECT * FROM db_version WHERE id = 4);
