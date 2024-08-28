INSERT INTO revocation_request_status(id, status_name) SELECT 0, 'NEW' WHERE NOT EXISTS (SELECT * FROM revocation_request_status WHERE Id = 0 and status_name='NEW');
INSERT INTO revocation_request_status(id, status_name) SELECT 1, 'REVOKED' WHERE NOT EXISTS (SELECT * FROM revocation_request_status WHERE Id = 1 and status_name='REVOKED');
INSERT INTO revocation_request_status(id, status_name) SELECT 2, 'FAILED' WHERE NOT EXISTS (SELECT * FROM revocation_request_status WHERE Id = 2 and status_name='FAILED');


INSERT INTO crl_status(id, status_name) SELECT 1, 'LATEST' WHERE NOT EXISTS (SELECT * FROM crl_status WHERE Id = 1 and status_name='LATEST');
INSERT INTO crl_status(id, status_name) SELECT 2, 'OLD' WHERE NOT EXISTS (SELECT * FROM crl_status WHERE Id = 2 and status_name='OLD');
INSERT INTO crl_status(id, status_name) SELECT 3, 'INVALID' WHERE NOT EXISTS (SELECT * FROM crl_status WHERE Id = 3 and status_name='INVALID');
INSERT INTO crl_status(id, status_name) SELECT 4, 'EXPIRED' WHERE NOT EXISTS (SELECT * FROM crl_status WHERE Id = 4 and status_name='EXPIRED');