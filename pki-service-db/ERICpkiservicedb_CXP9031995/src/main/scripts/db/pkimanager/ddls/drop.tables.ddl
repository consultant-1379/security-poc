ALTER TABLE IF EXISTS ca_certificate
DROP CONSTRAINT IF EXISTS fk_ca_certificate_caentity_id;

ALTER TABLE IF EXISTS ca_certificate
DROP CONSTRAINT IF EXISTS fk_ca_certificate_certificate_id;

DROP TABLE IF EXISTS ca_certificate;

ALTER TABLE IF EXISTS entity_certificate
DROP CONSTRAINT IF EXISTS fk_entity_certificate_certificate_id;

ALTER TABLE IF EXISTS entity_certificate
DROP CONSTRAINT IF EXISTS fk_entity_certificate_entity_id;

DROP TABLE IF EXISTS entity_certificate;

ALTER TABLE IF EXISTS certificateProfile_keygenerationalgorithm
DROP CONSTRAINT IF EXISTS fk_certificateprofile_keygenerationalgorithm_algorithm_id;

ALTER TABLE IF EXISTS certificateprofile_keygenerationalgorithm
DROP CONSTRAINT IF EXISTS fk_certificateprofile_keygenerationalgorithm_certificateprofile_id;

DROP TABLE IF EXISTS certificateprofile_keygenerationalgorithm;

ALTER TABLE IF EXISTS entityprofile_trustprofile
DROP CONSTRAINT IF EXISTS fk_entityprofile_trustprofile_entityprofile_id;

ALTER TABLE IF EXISTS entityprofile_trustprofile
DROP CONSTRAINT IF EXISTS fk_entityprofile_trustprofile_trustprofile_id;

DROP TABLE IF EXISTS entityprofile_trustprofile;


ALTER TABLE IF EXISTS trustprofile_externalca
DROP CONSTRAINT IF EXISTS fk_trustprofile_externalca_caentity_id;

ALTER TABLE IF EXISTS trustprofile_externalca
DROP CONSTRAINT IF EXISTS fk_trustprofile_externalca_trustprofile_id;

DROP TABLE IF EXISTS trustprofile_externalca;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_request_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_algorithm_signature_algorithm_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_caentity_ca_entity_info_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_entity_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_caentity_issuer_ca_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_algorithm_key_generation_algorithm_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_certificate_version_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_certificate_generation_info_request_type_id;

ALTER TABLE IF EXISTS certificate_generation_info
DROP CONSTRAINT IF EXISTS fk_cert_gen_info_alg_id;

DROP TABLE IF EXISTS certificate_generation_info;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_caentity_id;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_certificate_status_id;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_certificate_issuer_certificate_id;

ALTER TABLE IF EXISTS certificate
DROP COLUMN IF EXISTS issuer_certificate_id;

ALTER TABLE IF EXISTS certificate
DROP COLUMN IF EXISTS revoked_time;

ALTER TABLE IF EXISTS certificate
DROP CONSTRAINT IF EXISTS fk_cert_cert_category_id;

ALTER TABLE IF EXISTS entity
DROP CONSTRAINT IF EXISTS fk_entity_algorithm_id;

ALTER TABLE IF EXISTS entity
DROP CONSTRAINT IF EXISTS fk_entity_entity_category_id;

ALTER TABLE IF EXISTS entity
DROP CONSTRAINT IF EXISTS fk_entity_caentity_id;

ALTER TABLE IF EXISTS entity
DROP CONSTRAINT IF EXISTS fk_entity_entityprofile_id;

ALTER TABLE IF EXISTS entity
DROP CONSTRAINT IF EXISTS fk_entity_entity_status_id;

ALTER TABLE IF EXISTS certificate_request
DROP CONSTRAINT IF EXISTS fk_certificate_request_certificate_request_status_id;

DROP TABLE IF EXISTS certificate_request;

ALTER TABLE IF EXISTS caentityassociation
DROP CONSTRAINT IF EXISTS fk_caentityassociation_caentity_id;

ALTER TABLE IF EXISTS caentityassociation
DROP CONSTRAINT IF EXISTS fk_caentityassociation_caentity_associatedcaentity_id;

DROP TABLE IF EXISTS caentityassociation;

ALTER TABLE IF EXISTS trustcachain
DROP CONSTRAINT IF EXISTS fk_trustcachain_trustprofile_id;

ALTER TABLE IF EXISTS trustcachain
DROP CONSTRAINT IF EXISTS fk_trustcachain_caentity_id;

DROP TABLE IF EXISTS trustcachain;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_caentity_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_entityprofile_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_externalcrlinfo_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_algorithm_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_ca_status_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_ca_configuration_id;

ALTER TABLE IF EXISTS caentity
DROP CONSTRAINT IF EXISTS fk_caentity_ca_config_id;

DROP TABLE IF EXISTS ca_configuration;

ALTER TABLE IF EXISTS certificateprofile
DROP CONSTRAINT IF EXISTS fk_certificateprofile_caentity_id;

ALTER TABLE IF EXISTS entityprofile
DROP CONSTRAINT IF EXISTS fk_entityprofile_entity_category_id;

ALTER TABLE IF EXISTS entityprofile
DROP CONSTRAINT IF EXISTS fk_entityprofile_certificateprofile_id;

ALTER TABLE IF EXISTS entityprofile
DROP CONSTRAINT IF EXISTS fk_entityprofile_algorithm_id;

DROP TABLE IF EXISTS entityprofile;

ALTER TABLE IF EXISTS certificateprofile
DROP CONSTRAINT IF EXISTS fk_certificateprofile_algorithm_id;

ALTER TABLE IF EXISTS certificateprofile
DROP CONSTRAINT IF EXISTS fk_certificateprofile_certificate_version_id;

DROP TABLE IF EXISTS certificateprofile;

DROP TABLE IF EXISTS trustprofile;

ALTER TABLE IF EXISTS algorithm_algorithmcategory
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithmcategory_algorithmcategory_id;

ALTER TABLE IF EXISTS algorithm_algorithmcategory
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithmcategory_algorithm_id;

DROP TABLE IF EXISTS algorithm_algorithmcategory;

DROP TABLE IF EXISTS externalcrlinfo;

ALTER TABLE IF EXISTS algorithm
DROP CONSTRAINT IF EXISTS fk_algorithm_algorithm_type_id;

# added for custom-configuration table 
ALTER TABLE IF EXISTS custom_configuration
DROP CONSTRAINT IF EXISTS pk_custom_configuration_id ;

ALTER TABLE IF EXISTS custom_configuration
DROP CONSTRAINT IF EXISTS uk_custom_configuration_name_owner;

DROP TABLE IF EXISTS custom_configuration;


DROP TABLE IF EXISTS entity_status;
DROP TABLE IF EXISTS certificate_status;
DROP TABLE IF EXISTS ca_status;
DROP TABLE IF EXISTS entity_category;
DROP TABLE IF EXISTS algorithmcategory;
DROP TABLE IF EXISTS certificate_version;
DROP TABLE IF EXISTS algorithm_type;
DROP TABLE IF EXISTS certificate_request_status;
DROP TABLE IF EXISTS request_type;
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

--Added for crl
ALTER TABLE IF EXISTS ca_crlinfo
DROP CONSTRAINT IF EXISTS fk_crlinfo_id;

ALTER TABLE IF EXISTS ca_crlinfo
DROP CONSTRAINT IF EXISTS fk_caentity_id;

DROP TABLE IF EXISTS ca_crlinfo;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_certificate_id;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_crl_id;

ALTER TABLE IF EXISTS crlinfo
DROP CONSTRAINT IF EXISTS fk_status;

DROP TABLE IF EXISTS crl_status;

DROP TABLE IF EXISTS crlinfo;

DROP TABLE IF EXISTS crl;
--Added for crl end--

--Added for crlgenerationinfo---
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

--Added for crlgenerationinfo end---

ALTER TABLE IF EXISTS certificate_expiry_notification_details
DROP CONSTRAINT IF EXISTS fk_cert_exp_not_details_not_severity_id;

DROP TABLE IF EXISTS notification_severity;

ALTER TABLE IF EXISTS ca_cert_exp_notification_details
DROP CONSTRAINT IF EXISTS fk_ca_cert_exp_not_details_caentity_id;

ALTER TABLE IF EXISTS ca_cert_exp_notification_details
DROP CONSTRAINT IF EXISTS fk_ca_cert_exp_not_details_cert_exp_not_det_id;

DROP TABLE IF EXISTS ca_cert_exp_notification_details;

ALTER TABLE IF EXISTS entity_cert_exp_notification_details
DROP CONSTRAINT IF EXISTS fk_entity_cert_exp_not_details_entity_id;

ALTER TABLE IF EXISTS entity_cert_exp_notification_details
DROP CONSTRAINT IF EXISTS fk_entity_cert_exp_not_details_cert_exp_not_det_id;

DROP TABLE IF EXISTS entity_cert_exp_notification_details;

DROP TABLE IF EXISTS certificate_expiry_notification_details;

DROP TABLE IF EXISTS certificate_category;

DROP TABLE IF EXISTS ca_configuration;

DROP SEQUENCE IF EXISTS SEQ_CERT_EXP_NOT_ID;

DROP TABLE IF EXISTS certificate;
DROP TABLE IF EXISTS entity;
DROP TABLE IF EXISTS caentity;
DROP TABLE IF EXISTS algorithm;

DROP SEQUENCE IF EXISTS SEQ_CA_CONFIG_ID;

DROP SEQUENCE IF EXISTS SEQ_REVOCATION_REQUEST_ID;
DROP SEQUENCE IF EXISTS SEQ_CRL_ID;
DROP SEQUENCE IF EXISTS SEQ_CRLINFO_ID;
DROP SEQUENCE IF EXISTS SEQ_CRL_GENERATION_INFO_ID;

DROP SEQUENCE IF EXISTS SEQ_ENTITY_ID;
DROP SEQUENCE IF EXISTS SEQ_PROFILE_ID;
DROP SEQUENCE IF EXISTS SEQ_CA_ID;
DROP SEQUENCE IF EXISTS SEQ_ALGORITHM_ID;
DROP SEQUENCE IF EXISTS SEQ_ENTITY_CATEGORY_ID;
DROP SEQUENCE IF EXISTS SEQ_EXT_CRL_ID;
DROP SEQUENCE IF EXISTS SEQ_CERTIFICATE_GENERATION_INFO_ID;
DROP SEQUENCE IF EXISTS SEQ_CERTIFICATE_REQUEST_ID;
DROP SEQUENCE IF EXISTS SEQ_CERTIFICATE_ID;
DROP SEQUENCE IF EXISTS DB_VERSION_ID;

#add for custom configuration table
DROP SEQUENCE IF EXISTS SEQ_CUSTOM_CONFIGURATION_ID ;
