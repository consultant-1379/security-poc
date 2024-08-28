ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_request_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_signature_algorithm_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_authority_ca_entity_info_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_entity_info_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_authority_issuer_ca_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_key_generation_algorithm_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_version_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_request_type_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_cert_gen_info_alg_id;

DROP TABLE IF EXISTS certificate_generation_info;

ALTER TABLE IF EXISTS ca_certificate
DROP CONSTRAINT IF EXISTS fk_ca_certificate_certificate_authority_id;

ALTER TABLE IF EXISTS ca_certificate
DROP CONSTRAINT IF EXISTS fk_ca_certificate_certificate_id;

DROP TABLE IF EXISTS ca_certificate;

ALTER TABLE IF EXISTS entity_certificate
DROP CONSTRAINT IF EXISTS fk_entity_certificate_certificate_id;

ALTER TABLE IF EXISTS entity_certificate
DROP CONSTRAINT IF EXISTS fk_entity_certificate_entity_info_id;

DROP TABLE IF EXISTS entity_certificate;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_certificate_authority_id;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_certificate_status_id;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_issuer_certificate_id;

ALTER TABLE IF EXISTS certificate
DROP COLUMN IF EXISTS issuer_certificate_id;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_cert_cert_category_id;

ALTER TABLE IF EXISTS algorithm_algorithmcategory
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithmcategory_algorithmcategory_id;

ALTER TABLE IF EXISTS algorithm_algorithmcategory
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithmcategory_algorithm_id;

DROP TABLE IF EXISTS algorithm_algorithmcategory;

ALTER TABLE IF EXISTS algorithm
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithm_type_id;

ALTER TABLE IF EXISTS entity_info
DROP CONSTRAINT IF EXISTS fk_entity_info_certificate_authority_id;

ALTER TABLE IF EXISTS entity_info
DROP CONSTRAINT IF EXISTS fk_entity_info_entity_status_id;

ALTER TABLE IF EXISTS certificate_request
DROP CONSTRAINT IF EXISTS fk_certificate_request_certificate_request_status_id;

DROP TABLE IF EXISTS certificate_request;

DROP TABLE IF EXISTS certificate_request_status;

DROP TABLE IF EXISTS request_type;

DROP TABLE IF EXISTS algorithm_type;

DROP TABLE IF EXISTS certificate_version;

ALTER TABLE IF EXISTS ca_keys
DROP CONSTRAINT IF EXISTS fk_ca_keys_certificate_authority_id;

ALTER TABLE IF EXISTS ca_keys
DROP CONSTRAINT IF EXISTS fk_ca_keys_key_identifier_id;

DROP TABLE IF EXISTS ca_keys;

ALTER TABLE IF EXISTS keys
DROP CONSTRAINT IF EXISTS fk_keys_keypair_status_id;
  
DROP TABLE IF EXISTS keys;

ALTER TABLE IF EXISTS key_identifier
DROP CONSTRAINT IF EXISTS fk_key_identifier_keypair_status_id;

DROP TABLE IF EXISTS keypair_status;


ALTER TABLE IF EXISTS certificate_authority
DROP CONSTRAINT IF EXISTS fk_certificate_authority_certificate_authority_id;

ALTER TABLE IF EXISTS certificate_authority
DROP CONSTRAINT IF EXISTS fk_certificate_authority_ca_status_id;

DROP TABLE IF EXISTS algorithmcategory;

DROP TABLE IF EXISTS entity_status;
DROP TABLE IF EXISTS certificate_status;
DROP TABLE IF EXISTS ca_status;
DROP TABLE IF EXISTS db_version;

ALTER TABLE IF EXISTS revocation_request_certificate
DROP CONSTRAINT IF EXISTS fk_revocation_request_id;

ALTER TABLE IF EXISTS revocation_request_certificate
DROP CONSTRAINT IF EXISTS fk_revocation_request_certificate;

DROP TABLE IF EXISTS revocation_request_certificate;

ALTER TABLE IF EXISTS revocation_request
DROP CONSTRAINT IF EXISTS fk_revocation_request_caentity_id;

ALTER TABLE IF EXISTS revocation_request
DROP CONSTRAINT IF EXISTS fk_revocation_request_entity_id;

ALTER TABLE IF EXISTS revocation_request
DROP CONSTRAINT IF EXISTS fk_revocation_request_revocation_status;

DROP TABLE IF EXISTS revocation_request;

DROP TABLE IF EXISTS revocation_request_status;

--Added for crlgenerationinfo--
ALTER TABLE IF EXISTS crl_generation_info_ca_certificate
DROP CONSTRAINT IF EXISTS fk_crl_generation_info_id;

ALTER TABLE IF EXISTS crl_generation_info_ca_certificate
DROP CONSTRAINT IF EXISTS fk_certificate_id;

DROP TABLE IF EXISTS crl_generation_info_ca_certificate;

ALTER TABLE IF EXISTS ca_crl_generation_info
DROP CONSTRAINT IF EXISTS fk_caentity_id;

ALTER TABLE IF EXISTS ca_crl_generation_info
DROP CONSTRAINT IF EXISTS fk_crlinfo_id;

DROP TABLE IF EXISTS ca_crl_generation_info;

ALTER TABLE IF EXISTS crl_generation_info
DROP CONSTRAINT IF EXISTS fk_algorithm_id;

DROP TABLE IF EXISTS crl_generation_info;

--Added for crlgenerationinfo end--

--Added for crl
ALTER TABLE IF EXISTS ca_crlinfo
DROP CONSTRAINT IF EXISTS fk_crlinfo_id;

ALTER TABLE IF EXISTS ca_crlinfo
DROP CONSTRAINT IF EXISTS fk_certificate_authority_id;

DROP TABLE IF EXISTS ca_crlinfo;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_certificate_id;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_crl;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_status;

DROP TABLE IF EXISTS crl_status;

DROP TABLE IF EXISTS crlinfo;

DROP TABLE IF EXISTS crl;
--Added for crl end--

DROP TABLE IF EXISTS certificate;
DROP TABLE IF EXISTS key_identifier;
DROP TABLE IF EXISTS entity_info;
DROP TABLE IF EXISTS certificate_authority;
DROP TABLE IF EXISTS algorithm;

DROP SEQUENCE IF EXISTS SEQ_REVOCATION_REQUEST_ID;
DROP SEQUENCE IF EXISTS SEQ_CRL_ID;
DROP SEQUENCE IF EXISTS SEQ_CRLINFO_ID;
DROP SEQUENCE IF EXISTS SEQ_CRL_GENERATION_INFO_ID;


DROP SEQUENCE IF EXISTS SEQ_KEYS_ID;
DROP SEQUENCE IF EXISTS SEQ_ALGORITHM_ID;
DROP SEQUENCE IF EXISTS SEQ_KEY_IDENTIFIER_ID;
DROP SEQUENCE IF EXISTS SEQ_CERTIFICATE_ID;
DROP SEQUENCE IF EXISTS SEQ_CERTIFICATE_REQUEST_ID;
DROP SEQUENCE IF EXISTS DB_VERSION_ID;

DROP TABLE IF EXISTS certificate_category;