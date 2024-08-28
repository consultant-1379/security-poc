-- static table to indicate certificate categories.
CREATE TABLE IF NOT EXISTS certificate_category
(
 id integer NOT NULL,
 type character varying(255) NOT NULL,
 CONSTRAINT pk_certificate_category_id PRIMARY KEY (id)
 )
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_category OWNER TO pkimanagergrp;

-- column certificate_category to indicate to which category certificate belongs to.
SELECT add_column_if_not_exists('certificate', 'certificate_category', 'ALTER TABLE IF EXISTS certificate ADD COLUMN certificate_category integer');

SELECT create_constraint_if_not_exists('certificate_category','fk_cert_cert_category_id','ALTER TABLE IF EXISTS certificate
	ADD CONSTRAINT fk_cert_cert_category_id FOREIGN KEY (certificate_category)
		REFERENCES certificate_category (id) MATCH SIMPLE
		ON UPDATE NO ACTION ON DELETE NO ACTION');

-- column issuer_signature_algorithm to store issuer's signature algorithm
SELECT add_column_if_not_exists('certificate_generation_info', 'issuer_signature_algorithm', 'ALTER TABLE IF EXISTS certificate_generation_info ADD COLUMN issuer_signature_algorithm bigint');

SELECT create_constraint_if_not_exists('algorithm','fk_cert_gen_info_alg_id','ALTER TABLE IF EXISTS certificate_generation_info
	ADD CONSTRAINT fk_cert_gen_info_alg_id FOREIGN KEY (issuer_signature_algorithm)
		REFERENCES algorithm (id) MATCH SIMPLE
		ON UPDATE NO ACTION ON DELETE NO ACTION');

-- column subject_unique_identifier_value to store subject unique identifier value
SELECT add_column_if_not_exists('certificate_generation_info', 'subject_unique_identifier_value', 'ALTER TABLE IF EXISTS certificate_generation_info ADD COLUMN subject_unique_identifier_value text');

-- column issuer_unique_identifier_value to store issuer unique identifier value
SELECT add_column_if_not_exists('certificate_generation_info', 'issuer_unique_identifier_value', 'ALTER TABLE IF EXISTS certificate_generation_info ADD COLUMN issuer_unique_identifier_value text');

-- column subject_unique_identifier_value to store ca entity subject unique identifier value
SELECT add_column_if_not_exists('caentity', 'subject_unique_identifier_value', 'ALTER TABLE IF EXISTS caentity ADD COLUMN subject_unique_identifier_value text');

-- column subject_unique_identifier_value to store entity subject unique identifier value
SELECT add_column_if_not_exists('entity', 'subject_unique_identifier_value', 'ALTER TABLE IF EXISTS entity ADD COLUMN subject_unique_identifier_value text');

-- column subject_unique_identifier_value to store entity profile subject unique identifier value
SELECT add_column_if_not_exists('entityprofile', 'subject_unique_identifier_value', 'ALTER TABLE IF EXISTS entityprofile ADD COLUMN subject_unique_identifier_value text');

-- table for storing notification severities
CREATE TABLE IF NOT EXISTS notification_severity
(
 id integer NOT NULL,
 status character varying(255) NOT NULL,
 CONSTRAINT pk_notification_severity_id PRIMARY KEY (id)
 )
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS notification_severity OWNER TO pkimanagergrp;

-- sequence for certificate_expiry_notification_details table
SELECT create_sequence_if_not_exists('seq_cert_exp_not_id','CREATE SEQUENCE SEQ_CERT_EXP_NOT_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERT_EXP_NOT_ID OWNER TO pkimanagergrp;

-- table to store ca/entity certificate exprity notification deatils
CREATE TABLE IF NOT EXISTS certificate_expiry_notification_details
(
 id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CERT_EXP_NOT_ID'),
 notification_severity integer NOT NULL,
 period_before_expiry integer NOT NULL,
 frequency_of_notification integer NOT NULL,
 notification_message text NOT NULL,
 CONSTRAINT pk_cert_exp_not_details_id PRIMARY KEY (id),
 CONSTRAINT fk_cert_exp_not_details_not_severity_id FOREIGN KEY (notification_severity)
		REFERENCES notification_severity (id) MATCH SIMPLE
		ON UPDATE NO ACTION ON DELETE NO ACTION)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_expiry_notification_details OWNER TO pkimanagergrp;

-- table for mapping ca and certificate expiry notification details.
CREATE TABLE IF NOT EXISTS ca_cert_exp_notification_details
(
 ca_id bigint NOT NULL,
 ca_cert_exp_not_details_id bigint NOT NULL,
 CONSTRAINT pk_ca_cert_exp_not_details_id PRIMARY KEY (ca_id, ca_cert_exp_not_details_id),
 CONSTRAINT fk_ca_cert_exp_not_details_caentity_id FOREIGN KEY (ca_id)
     REFERENCES caentity (id) MATCH SIMPLE
     ON UPDATE NO ACTION ON DELETE NO ACTION,
 CONSTRAINT fk_ca_cert_exp_not_details_cert_exp_not_det_id FOREIGN KEY (ca_cert_exp_not_details_id)
     REFERENCES certificate_expiry_notification_details (id) MATCH SIMPLE
     ON UPDATE NO ACTION ON DELETE NO ACTION,
 CONSTRAINT uk_ca_cert_exp_not_det_id UNIQUE (ca_cert_exp_not_details_id)
)
WITH (
 OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_cert_exp_notification_details OWNER TO pkimanagergrp;

-- table for mapping entity and certificate expiry notification details.
CREATE TABLE IF NOT EXISTS entity_cert_exp_notification_details
(
 entity_id bigint NOT NULL,
 entity_cert_exp_not_details_id bigint NOT NULL,
 CONSTRAINT pk_entity_cert_exp_not_details_id PRIMARY KEY (entity_id, entity_cert_exp_not_details_id),
 CONSTRAINT fk_entity_cert_exp_not_details_entity_id FOREIGN KEY (entity_id)
     REFERENCES entity (id) MATCH SIMPLE
     ON UPDATE NO ACTION ON DELETE NO ACTION,
 CONSTRAINT fk_entity_cert_exp_not_details_cert_exp_not_det_id FOREIGN KEY (entity_cert_exp_not_details_id)
     REFERENCES certificate_expiry_notification_details (id) MATCH SIMPLE
     ON UPDATE NO ACTION ON DELETE NO ACTION,
 CONSTRAINT uk_entity_cert_exp_not_det_id UNIQUE (entity_cert_exp_not_details_id)
)
WITH (
 OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_cert_exp_notification_details OWNER TO pkimanagergrp;
