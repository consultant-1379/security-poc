-- static data to indicate certificate categories.
INSERT INTO certificate_category(id, type) SELECT 1, 'INTERNAL_CA' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 1 and type='INTERNAL_CA');
INSERT INTO certificate_category(id, type) SELECT 2, 'EXTERNAL_CA' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 2 and type='EXTERNAL_CA');
INSERT INTO certificate_category(id, type) SELECT 3, 'ENTITY' WHERE NOT EXISTS (SELECT * FROM certificate_category WHERE id = 3 and type='ENTITY');