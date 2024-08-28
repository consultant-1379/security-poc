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
ALTER TABLE IF EXISTS certificate_category OWNER TO pkicoregrp;

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