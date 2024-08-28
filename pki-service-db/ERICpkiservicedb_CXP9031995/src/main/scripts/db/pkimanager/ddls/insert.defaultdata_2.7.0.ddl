-- static data to indicate certificate categories.
INSERT INTO certificate_category(id, type) SELECT 1, 'INTERNAL_CA' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 1 and type='INTERNAL_CA');
INSERT INTO certificate_category(id, type) SELECT 2, 'EXTERNAL_CA' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 2 and type='EXTERNAL_CA');
INSERT INTO certificate_category(id, type) SELECT 3, 'ENTITY' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 3 and type='ENTITY');

-- static data for notification severities
INSERT INTO notification_severity(id, status) SELECT 1, 'CRITICAL' WHERE NOT EXISTS (SELECT * FROM notification_severity WHERE id = 1 and status='CRITICAL');
INSERT INTO notification_severity(id, status) SELECT 2, 'MAJOR' WHERE NOT EXISTS (SELECT * FROM notification_severity WHERE id = 2 and status='MAJOR');
INSERT INTO notification_severity(id, status) SELECT 3, 'WARNING' WHERE NOT EXISTS (SELECT * FROM notification_severity WHERE id = 3 and status='WARNING');
INSERT INTO notification_severity(id, status) SELECT 4, 'MINOR' WHERE NOT EXISTS (SELECT * FROM notification_severity WHERE id = 4 and status='MINOR');