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

CREATE TABLE IF NOT EXISTS algorithm_type
(
  id integer NOT NULL,
  type character varying(255) NOT NULL,
  CONSTRAINT pk_algorithm_type_id PRIMARY KEY (id),
  CONSTRAINT uc_algorithm_type_id UNIQUE (type)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithm_type
  OWNER TO pkicore;
  
  CREATE TABLE IF NOT EXISTS keypair_status
(
  Id INTEGER NOT NULL,
  Status_Name CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_keypair_status_id PRIMARY KEY (Id),
  CONSTRAINT uc_keypair_status_id UNIQUE (Status_Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS keypair_status
  OWNER TO pkicore;
  
  CREATE TABLE IF NOT EXISTS certificate_request_status
(
  Id INTEGER NOT NULL,
  Status_Name CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_certificate_request_status_id PRIMARY KEY (Id),
  CONSTRAINT uc_certificate_request_status_id UNIQUE (Status_Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_request_status
  OWNER TO pkicore;
  
  
CREATE TABLE IF NOT EXISTS certificate_version
(
  Id INTEGER NOT NULL,
  version CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_certificate_version_id PRIMARY KEY (Id),
  CONSTRAINT uc_certificate_version_id UNIQUE (version)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_version
  OWNER TO pkicore;
  
  CREATE TABLE IF NOT EXISTS request_type
(
  Id INTEGER NOT NULL,
  type CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_request_type_id PRIMARY KEY (Id),
  CONSTRAINT uc_request_type_id UNIQUE (type)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS request_type
  OWNER TO pkicore;

SELECT create_sequence_if_not_exists('seq_algorithm_id','CREATE SEQUENCE SEQ_ALGORITHM_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ALGORITHM_ID OWNER TO pkicore;

CREATE TABLE IF NOT EXISTS algorithm
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_ALGORITHM_ID'),
  key_size integer,
  name character varying(255),
  oid character varying(255),
  is_supported boolean,
  type_id integer NOT NULL,
  CONSTRAINT pk_algorithm_id PRIMARY KEY (id),
  CONSTRAINT uc_algorithm_id UNIQUE (name, key_size),
  CONSTRAINT fk_algorithm_algorithm_type_id FOREIGN KEY (type_id)
      REFERENCES algorithm_type (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS algorithm
  OWNER TO pkicore;
 
  
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
  OWNER TO pkicore;

  
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
  OWNER TO pkicore;

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
  OWNER TO pkicore;
  
  
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
  OWNER TO pkicore;
  
  
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
  OWNER TO pkicore;  
  
  
  
CREATE TABLE IF NOT EXISTS certificate_authority
(
  id bigint NOT NULL,
  name character varying(255) NOT NULL,
  is_root_ca boolean NOT NULL,
  status_id integer NOT NULL,
  subject_alt_name text,
  subject_dn text,
  issuer_id bigint,
  CONSTRAINT pk_certificate_authority_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_authority_certificate_authority_id FOREIGN KEY (issuer_id)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_certificate_authority_id UNIQUE (name),
  CONSTRAINT fk_certificate_authority_ca_status_id FOREIGN KEY (status_id)
      REFERENCES ca_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate_authority
  OWNER TO pkicore;
  
SELECT create_sequence_if_not_exists('seq_key_identifier_id','CREATE SEQUENCE SEQ_KEY_IDENTIFIER_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_KEY_IDENTIFIER_ID OWNER TO pkicore;

CREATE TABLE IF NOT EXISTS key_identifier
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_KEY_IDENTIFIER_ID'::regclass),
  key_identifier_id character varying(255) NOT NULL,
  status_id integer NOT NULL,
  CONSTRAINT pk_key_identifier_id PRIMARY KEY (id),
  CONSTRAINT uc_key_identifier_id UNIQUE (key_identifier_id),
  CONSTRAINT fk_key_identifier_keypair_status_id FOREIGN KEY (status_id)
      REFERENCES keypair_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS key_identifier
  OWNER TO pkicore;
  
  
CREATE TABLE IF NOT EXISTS ca_keys
(
  ca_id bigint NOT NULL,
  key_id bigint NOT NULL,
  CONSTRAINT pk_ca_keys_id PRIMARY KEY (ca_id, key_id),
  CONSTRAINT fk_ca_keys_certificate_authority_id FOREIGN KEY (ca_id)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_ca_keys_key_identifier_id FOREIGN KEY (key_id)
      REFERENCES key_identifier (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_ca_keys_id  UNIQUE (key_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_keys
  OWNER TO pkicore;

  
SELECT create_sequence_if_not_exists('seq_certificate_id','CREATE SEQUENCE SEQ_CERTIFICATE_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_ID OWNER TO pkicore;

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
  key_id bigint,
  CONSTRAINT pk_certificate_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_certificate_authority_id FOREIGN KEY (issuer_id)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_key_identifier_id FOREIGN KEY (key_id)
      REFERENCES key_identifier (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_certificate_status_id FOREIGN KEY (status_id)
      REFERENCES certificate_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS certificate  
  OWNER TO pkicore;
  
CREATE TABLE IF NOT EXISTS ca_certificate
(
  ca_id bigint NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_ca_certificate_id PRIMARY KEY (ca_id, certificate_id),
  CONSTRAINT fk_ca_certificate_certificate_authority_id FOREIGN KEY (ca_id)
      REFERENCES certificate_authority (id) MATCH SIMPLE
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
  OWNER TO pkicore;

SELECT create_sequence_if_not_exists('seq_certificate_request_id','CREATE SEQUENCE SEQ_CERTIFICATE_REQUEST_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_REQUEST_ID OWNER TO pkicore;

CREATE TABLE IF NOT EXISTS certificate_request
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CERTIFICATE_REQUEST_ID'),
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
  OWNER TO pkicore;
  
  
 CREATE TABLE IF NOT EXISTS entity_info
(
  id bigint NOT NULL,
  name character varying(255) NOT NULL,
  otp character varying(255),
  otp_count integer,
  status_id integer NOT NULL,
  subject_alt_name text,
  subject_dn text,
  issuer_id bigint,
  CONSTRAINT pk_entity_info_id PRIMARY KEY (id),
  CONSTRAINT fk_entity_info_certificate_authority_id FOREIGN KEY (issuer_id)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entity_info_entity_status_id FOREIGN KEY (status_id)
      REFERENCES entity_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_entity_info_id UNIQUE (name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_info  
  OWNER TO pkicore;
 
  
CREATE TABLE IF NOT EXISTS certificate_generation_info
(
  id bigint NOT NULL,
  certificate_extensions text,
  certificate_version integer NOT NULL,
  issuer_unique_identifier boolean NOT NULL,
  request_type integer NOT NULL,
  skew_certificate_time character varying(10),
  subject_unique_identifier boolean NOT NULL,
  validity character varying(10) NOT NULL,
  ca_entity_info bigint,
  certificate_id bigint,
  certificate_request_id bigint,
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
  CONSTRAINT fk_certificate_generation_info_signature_algorithm_id FOREIGN KEY (signature_algorithm)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_certificate_authority_ca_entity_info_id FOREIGN KEY (ca_entity_info)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_entity_info_id FOREIGN KEY (entity_info)
      REFERENCES entity_info (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_certificate_authority_issuer_ca_id FOREIGN KEY (issuer_ca)
      REFERENCES certificate_authority (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_generation_info_key_generation_algorithm_id FOREIGN KEY (key_generation_algorithm)
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
  OWNER TO pkicore;


CREATE TABLE IF NOT EXISTS entity_certificate
(
  entity_id bigint NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_entity_certificate_id PRIMARY KEY (entity_id, certificate_id),
  CONSTRAINT fk_entity_certificate_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_entity_certificate_entity_info_id FOREIGN KEY (entity_id)
      REFERENCES entity_info (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_entity_certificate_id UNIQUE (certificate_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS entity_certificate  
  OWNER TO pkicore;

  
  