CREATE OR REPLACE function create_sequence_if_not_exists (
    s_name text, sequence_sql text
) 
RETURNS void AS
$BODY$
BEGIN
    IF NOT EXISTS (SELECT 0 
                   FROM pg_class WHERE relname = s_name) THEN
        EXECUTE sequence_sql;
    END IF;
END;
$BODY$
LANGUAGE plpgsql
;


CREATE OR REPLACE function create_constraint_if_not_exists (
    t_name text, c_name text, constraint_sql text
) 
RETURNS void AS
$BODY$
BEGIN
    IF NOT EXISTS (SELECT constraint_name 
                   FROM information_schema.constraint_column_usage 
                   WHERE table_name = t_name  AND constraint_name = c_name) THEN
        EXECUTE constraint_sql;
    END IF;
END;
$BODY$
LANGUAGE plpgsql
;

CREATE TABLE IF NOT EXISTS algorithm_type
(
  Id integer NOT NULL,
  type character varying(255) NOT NULL,
  CONSTRAINT pk_algorithm_type_id PRIMARY KEY (Id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithm_type
  OWNER TO pkimanager;  
  
SELECT create_sequence_if_not_exists('seq_algorithm_id','CREATE SEQUENCE SEQ_ALGORITHM_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ALGORITHM_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS algorithm
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_ALGORITHM_ID'),
  key_size integer,
  name character varying(255),
  oid character varying(255),
  is_supported boolean,
  type_id integer NOT NULL,
  CONSTRAINT pk_algorithm_id PRIMARY KEY (id),
  CONSTRAINT fk_algorithm_algorithm_type_id FOREIGN KEY(type_id)
  	  REFERENCES algorithm_type(Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_algorithm_id UNIQUE (name, key_size)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithm
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS algorithmcategory
(
  id integer NOT NULL,
  category_name character varying(255) NOT NULL,
  CONSTRAINT pk_algorithmcategory_id PRIMARY KEY (id),
  CONSTRAINT uc_algoirthmcategory_id UNIQUE (category_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithmcategory
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS algorithm_algorithmcategory
(
  algorithm_id bigint NOT NULL,
  category_id integer NOT NULL,
  CONSTRAINT pk_algorithm_algorithmcategory_id PRIMARY KEY (algorithm_id, category_id),
  CONSTRAINT fk_algorithm_algorithmcategory_algorithmcategory_id FOREIGN KEY (category_id)
      REFERENCES algorithmcategory (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_algorithm_algorithmcategory_algorithm_id FOREIGN KEY (algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithm_algorithmcategory
  OWNER TO pkimanager;
  
  
  CREATE TABLE IF NOT EXISTS ca_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_ca_status_id PRIMARY KEY (id),
  CONSTRAINT uc_ca_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_status
  OWNER TO pkimanager;
  
  
  CREATE TABLE IF NOT EXISTS entity_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_entity_status_id PRIMARY KEY (id),
  CONSTRAINT uc_entity_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_status
  OWNER TO pkimanager;
  
  
  CREATE TABLE IF NOT EXISTS certificate_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_certificate_status_id PRIMARY KEY (id),
  CONSTRAINT uc_certificate_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_status
  OWNER TO pkimanager;
  
   SELECT create_sequence_if_not_exists('seq_entity_category_id','CREATE SEQUENCE SEQ_ENTITY_CATEGORY_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ENTITY_CATEGORY_ID OWNER TO pkimanager;
  
  
  CREATE TABLE IF NOT EXISTS entity_category
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_ENTITY_CATEGORY_ID'),
  modifiable boolean NOT NULL,
  name character varying(255) NOT NULL,
  CONSTRAINT pk_entity_category_id PRIMARY KEY (id),
  CONSTRAINT uc_entity_category_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_category
  OWNER TO pkimanager;
  
   SELECT create_sequence_if_not_exists('seq_ext_crl_id','CREATE SEQUENCE SEQ_EXT_CRL_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_EXT_CRL_ID OWNER TO pkimanager;

  CREATE TABLE IF NOT EXISTS externalcrlinfo
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_EXT_CRL_ID'),
  auto_update boolean NOT NULL,
  auto_update_check_timer integer,
  crl bytea NOT NULL,
  next_update timestamp without time zone NOT NULL,
  update_url character varying(255),
  CONSTRAINT pk_externalcrlinfo_id PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS externalcrlinfo
  OWNER TO pkimanager;

  
  SELECT create_sequence_if_not_exists('seq_ca_id','CREATE SEQUENCE SEQ_CA_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CA_ID OWNER TO pkimanager;

 CREATE TABLE IF NOT EXISTS caentity
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CA_ID'),
  publishcertificatetotdps boolean NOT NULL,
  name character varying(255) NOT NULL,
  is_root_ca boolean NOT NULL,
  status_id integer NOT NULL,
  subject_alt_name text,
  subject_dn text,
  is_external_ca boolean NOT NULL,
  entity_profile_id bigint,
  external_crl_info_id bigint,
  issuer_id bigint,
  key_generation_algorithm_id bigint,
  CONSTRAINT pk_caentity_id PRIMARY KEY (id),
  CONSTRAINT fk_caentity_caentity_id FOREIGN KEY (issuer_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_caentity_externalcrlinfo_id FOREIGN KEY (external_crl_info_id)
      REFERENCES externalcrlinfo (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_caentity_algorithm_id FOREIGN KEY (key_generation_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_caentity_ca_status_id FOREIGN KEY (status_id)
      REFERENCES ca_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_caentity_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS caentity
  OWNER TO pkimanager;

 CREATE TABLE IF NOT EXISTS certificate_version
(
  Id integer NOT NULL,
  version character varying(255) NOT NULL,
  CONSTRAINT pk_certificate_version_id PRIMARY KEY (Id),
  CONSTRAINT uc_certificate_version_id UNIQUE (version)

)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_version
  OWNER TO pkimanager;
  
  SELECT create_sequence_if_not_exists('seq_profile_id','CREATE SEQUENCE SEQ_PROFILE_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_PROFILE_ID OWNER TO pkimanager;
  
CREATE TABLE IF NOT EXISTS certificateprofile
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  is_active boolean NOT NULL,
  modifiable boolean NOT NULL,
  name character varying(255) NOT NULL,
  profile_validity timestamp without time zone,
  certificate_extensions text,
  for_ca_entity boolean NOT NULL,
  issuer_unique_identifier boolean NOT NULL,
  skew_certificate_time character varying(10),
  subject_capabilities text,
  subject_unique_identifier boolean NOT NULL,
  validity character varying(10) NOT NULL,
  version_id integer NOT NULL,
  issuer_id bigint,
  signature_algorithm_id bigint NOT NULL,
  CONSTRAINT pk_certificateprofile_id PRIMARY KEY (id),
  CONSTRAINT fk_certificateprofile_caentity_id FOREIGN KEY (issuer_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificateprofile_algorithm_id FOREIGN KEY (signature_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificateprofile_certificate_version_id FOREIGN KEY (version_id)
      REFERENCES certificate_version (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_certificateprofile_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificateprofile
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS entityprofile
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  is_active boolean NOT NULL,
  modifiable boolean NOT NULL,
  name character varying(255) NOT NULL,
  profile_validity timestamp without time zone,
  extended_key_usage_extension text,
  key_usage_extension text,
  subject_alt_name text,
  subject_dn text,
  certificate_profile_id bigint NOT NULL,
  entity_category_id bigint,
  key_generation_algorithm_id bigint,
  CONSTRAINT pk_entityprofile_id PRIMARY KEY (id),
  CONSTRAINT fk_entityprofile_entity_category_id FOREIGN KEY (entity_category_id)
      REFERENCES entity_category (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entityprofile_certificateprofile_id FOREIGN KEY (certificate_profile_id)
      REFERENCES certificateprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entityprofile_algorithm_id FOREIGN KEY (key_generation_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_entityprofile_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entityprofile
  OWNER TO pkimanager;
 
  
SELECT create_constraint_if_not_exists('entityprofile','fk_caentity_entityprofile_id','ALTER TABLE IF EXISTS caentity
ADD CONSTRAINT fk_caentity_entityprofile_id FOREIGN KEY (entity_profile_id)
REFERENCES entityprofile (id) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION');

SELECT create_sequence_if_not_exists('seq_certificate_id','CREATE SEQUENCE SEQ_CERTIFICATE_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS certificate
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CERTIFICATE_ID'),
  certificate bytea NOT NULL,
  issued_time timestamp without time zone NOT NULL,
  not_after timestamp without time zone NOT NULL,
  not_before timestamp without time zone NOT NULL,
  serial_number character varying(255) NOT NULL,
  status_id integer NOT NULL,
  subject_alt_name text,
  subject_dn text,
  issuer_id bigint,
  CONSTRAINT pk_certificate_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_caentity_id FOREIGN KEY (issuer_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_certificate_status_id FOREIGN KEY (status_id)
      REFERENCES certificate_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate
  OWNER TO pkimanager;
    
 CREATE TABLE IF NOT EXISTS ca_certificate
(
  ca_id bigint NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_ca_certificate_id PRIMARY KEY (ca_id, certificate_id),
  CONSTRAINT fk_ca_certificate_caentity_id FOREIGN KEY (ca_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_ca_certificate_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_ca_certificate_id UNIQUE (certificate_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_certificate
  OWNER TO pkimanager;


  
 CREATE TABLE IF NOT EXISTS caentityassociation
(
  caentity_id bigint NOT NULL,
  associatedcaentity_id bigint NOT NULL,
  CONSTRAINT pk_caentityassociation_id PRIMARY KEY (caentity_id, associatedcaentity_id),
  CONSTRAINT fk_caentityassociation_caentity_id FOREIGN KEY (caentity_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_caentityassociation_caentity_associatedcaentity_id FOREIGN KEY (associatedcaentity_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS caentityassociation
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS certificateprofile_keygenerationalgorithm
(
  certificate_profile_id bigint NOT NULL,
  key_generation_algorithm_id bigint NOT NULL,
  CONSTRAINT pk_certificateprofile_keygenerationalgorithm_id PRIMARY KEY (certificate_profile_id, key_generation_algorithm_id),
  CONSTRAINT fk_certificateprofile_keygenerationalgorithm_algorithm_id FOREIGN KEY (key_generation_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificateprofile_keygenerationalgorithm_certificateprofile_id FOREIGN KEY (certificate_profile_id)
      REFERENCES certificateprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificateprofile_keygenerationalgorithm
  OWNER TO pkimanager;

  SELECT create_sequence_if_not_exists('seq_entity_id','CREATE SEQUENCE SEQ_ENTITY_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ENTITY_ID OWNER TO pkimanager;

  CREATE TABLE IF NOT EXISTS entity
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_ENTITY_ID'),
  publishcertificatetotdps boolean NOT NULL,
  name character varying(255) NOT NULL,
  otp character varying(255),
  otp_count integer,
  status_id integer NOT NULL,
  subject_alt_name text,
  subject_dn text,
  entity_profile_id bigint,
  entity_category_id bigint,
  issuer_id bigint,
  key_generation_algorithm_id bigint,
  CONSTRAINT pk_entity_id PRIMARY KEY (id),
  CONSTRAINT fk_entity_algorithm_id FOREIGN KEY (key_generation_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entity_entity_category_id FOREIGN KEY (entity_category_id)
      REFERENCES entity_category (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE SET NULL,
  CONSTRAINT fk_entity_caentity_id FOREIGN KEY (issuer_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entity_entityprofile_id FOREIGN KEY (entity_profile_id)
      REFERENCES entityprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
   CONSTRAINT fk_entity_entity_status_id FOREIGN KEY (status_id)
      REFERENCES entity_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_entity_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS entity_certificate
(
  entity_id bigint NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_entity_certificate_id PRIMARY KEY (entity_id, certificate_id),
  CONSTRAINT fk_entity_certificate_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entity_certificate_entity_id FOREIGN KEY (entity_id)
      REFERENCES entity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_entity_certificate_id UNIQUE (certificate_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_certificate
  OWNER TO pkimanager;

  
   CREATE TABLE IF NOT EXISTS trustprofile
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  is_active boolean NOT NULL,
  modifiable boolean NOT NULL,
  name character varying(255) NOT NULL,
  profile_validity timestamp without time zone,
  CONSTRAINT pk_trustprofile_id PRIMARY KEY (id),
  CONSTRAINT uc_trustprofile_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS trustprofile
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS entityprofile_trustprofile
(
  entity_profile_id bigint NOT NULL,
  trust_profile_id bigint NOT NULL,
  CONSTRAINT pk_entityprofile_trustprofile_id PRIMARY KEY (entity_profile_id, trust_profile_id),
  CONSTRAINT fk_entityprofile_trustprofile_entityprofile_id FOREIGN KEY (entity_profile_id)
      REFERENCES entityprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entityprofile_trustprofile_trustprofile_id FOREIGN KEY (trust_profile_id)
      REFERENCES trustprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entityprofile_trustprofile
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS trustcachain
(
  is_chain_required boolean NOT NULL,
  caentity_id bigint NOT NULL,
  trustprofile_id bigint NOT NULL,
  CONSTRAINT pk_trustcachain_id PRIMARY KEY (caentity_id, trustprofile_id),
  CONSTRAINT fk_trustcachain_trustprofile_id FOREIGN KEY (trustprofile_id)
      REFERENCES trustprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_trustcachain_caentity_id FOREIGN KEY (caentity_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS trustcachain
  OWNER TO pkimanager;

  
  CREATE TABLE IF NOT EXISTS trustprofile_externalca
(
  trust_profile_id bigint NOT NULL,
  externalca_id bigint NOT NULL,
  CONSTRAINT pk_trustprofile_externalca_id PRIMARY KEY (trust_profile_id, externalca_id),
  CONSTRAINT fk_trustprofile_externalca_caentity_id FOREIGN KEY (externalca_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_trustprofile_externalca_trustprofile_id FOREIGN KEY (trust_profile_id)
      REFERENCES trustprofile (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS trustprofile_externalca
  OWNER TO pkimanager;
  
  
  CREATE TABLE IF NOT EXISTS certificate_request_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_certificate_request_status_id PRIMARY KEY (id),
  CONSTRAINT uc_certificate_request_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_request_status
  OWNER TO pkimanager;
  
  SELECT create_sequence_if_not_exists('seq_certificate_request_id','CREATE SEQUENCE SEQ_CERTIFICATE_REQUEST_ID START 1');
  ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_REQUEST_ID OWNER TO pkimanager;
  
  CREATE TABLE IF NOT EXISTS certificate_request
(
  id integer NOT NULL DEFAULT NEXTVAL('SEQ_CERTIFICATE_REQUEST_ID'),
  certificate_request bytea NOT NULL,
  status_id integer NOT NULL,
  CONSTRAINT pk_certificate_request_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_request_certificate_request_status_id FOREIGN KEY (status_id)
      REFERENCES certificate_request_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_request
  OWNER TO pkimanager;
  
  CREATE TABLE IF NOT EXISTS request_type
(
  id integer NOT NULL,
  type character varying(255) NOT NULL,
  CONSTRAINT pk_request_type_id PRIMARY KEY (id),
  CONSTRAINT uc_request_type_id UNIQUE (type)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS request_type
  OWNER TO pkimanager;
  

  SELECT create_sequence_if_not_exists('seq_certificate_generation_info_id','CREATE SEQUENCE SEQ_CERTIFICATE_GENERATION_INFO_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_GENERATION_INFO_ID OWNER TO pkimanager;

   CREATE TABLE IF NOT EXISTS certificate_generation_info
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CERTIFICATE_GENERATION_INFO_ID'),
  certificate_extensions text,
  certificate_version integer NOT NULL,
  is_latest_request boolean,
  issuer_unique_identifier boolean NOT NULL,
  request_type integer NOT NULL,
  skew_certificate_time character varying(10),
  subject_unique_identifier boolean NOT NULL,
  validity character varying(10) NOT NULL,
  ca_entity_info bigint,
  certificate_id bigint,
  certificate_request_id integer,
  entity_info bigint,
  issuer_ca bigint,
  key_generation_algorithm bigint NOT NULL,
  signature_algorithm bigint NOT NULL,
  CONSTRAINT pk_certificate_generation_info_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_generation_info_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_certificate_request_id FOREIGN KEY (certificate_request_id)
      REFERENCES certificate_request (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_algorithm_signature_algorithm_id FOREIGN KEY (signature_algorithm)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_caentity_ca_entity_info_id FOREIGN KEY (ca_entity_info)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_entity_id FOREIGN KEY (entity_info)
      REFERENCES entity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_caentity_issuer_ca_id FOREIGN KEY (issuer_ca)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_algorithm_key_generation_algorithm_id FOREIGN KEY (key_generation_algorithm)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_certificate_version_id FOREIGN KEY (certificate_version)
      REFERENCES certificate_version (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_request_type_id FOREIGN KEY (request_type)
      REFERENCES request_type (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_generation_info
  OWNER TO pkimanager;
  