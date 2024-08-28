SELECT add_column_if_not_exists('entity', 'name_alias', 'ALTER TABLE IF EXISTS entity ADD COLUMN name_alias character varying(255)');



SELECT create_sequence_if_not_exists('seq_subject_identification_details_id','CREATE SEQUENCE SEQ_SUBJECT_IDENTIFICATION_DETAILS_ID START 1');
CREATE TABLE IF NOT EXISTS subject_identification_details
(
	id bigint NOT NULL DEFAULT NEXTVAL('SEQ_SUBJECT_IDENTIFICATION_DETAILS_ID'),
	entity_id bigint NOT NULL,
	subject_dn_hash bytea,
	CONSTRAINT pk_entity_subject_dn_hash_id PRIMARY KEY (id)
)
WITH (
	OIDS=FALSE
);
