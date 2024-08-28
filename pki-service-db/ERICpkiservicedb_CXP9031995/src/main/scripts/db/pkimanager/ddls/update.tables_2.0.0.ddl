ALTER TABLE IF EXISTS certificate
ADD COLUMN issuer_certificate_id bigint;

ALTER TABLE IF EXISTS  certificate
ADD COLUMN  revoked_time timestamp without time zone;

ALTER TABLE IF EXISTS certificate
ADD CONSTRAINT fk_certificate_issuer_certificate_id FOREIGN KEY (issuer_certificate_id)
REFERENCES certificate (id) MATCH SIMPLE
ON UPDATE NO ACTION ON DELETE NO ACTION;

SELECT create_sequence_if_not_exists('seq_revocation_request_id','CREATE SEQUENCE SEQ_REVOCATION_REQUEST_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_REVOCATION_REQUEST_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS revocation_request_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_revocation_status_id PRIMARY KEY (id),
  CONSTRAINT uk_revocation_status_name UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS revocation_request_status
  OWNER TO pkimanager; 
  
CREATE TABLE IF NOT EXISTS revocation_request
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_REVOCATION_REQUEST_ID'),
  crl_entry_extensions text,
  status integer NOT NULL,
  ca_entity_id bigint,
  entity_id bigint,
  CONSTRAINT pk_revocation_request_id PRIMARY KEY (id),
  CONSTRAINT fk_revocation_request_caentity_id FOREIGN KEY (ca_entity_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_revocation_request_entity_id FOREIGN KEY (entity_id)
      REFERENCES entity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_revocation_request_revocation_status FOREIGN KEY (status)
      REFERENCES revocation_request_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS revocation_request
  OWNER TO pkimanager;
 
CREATE TABLE IF NOT EXISTS revocation_request_certificate
(
  revocation_id bigint NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_revocation_request_certificate_id PRIMARY KEY (revocation_id, certificate_id),
  CONSTRAINT fk_revocation_request_id FOREIGN KEY (revocation_id)
      REFERENCES revocation_request (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_revocation_request_certificate FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS revocation_request_certificate
  OWNER TO pkimanager;
  
-----Scripts added for crlgenerationinfo-------
  
SELECT create_sequence_if_not_exists('SEQ_CRL_GENERATION_INFO_ID','CREATE SEQUENCE SEQ_CRL_GENERATION_INFO_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CRL_GENERATION_INFO_ID OWNER TO pkimanager;
  
CREATE TABLE IF NOT EXISTS crl_generation_info
(
  id integer NOT NULL DEFAULT nextval('SEQ_CRL_GENERATION_INFO_ID'),
  validity_period character varying(30) NOT NULL,
  skew_crl_time character varying(30),
  overlap_period character varying(30),
  crl_extensions text,
  signature_algorithm_id bigint NOT NULL,
  version integer NOT NULL,
  CONSTRAINT pk_crl_generation_info_id PRIMARY KEY (id),
  CONSTRAINT fk_algorithm_id FOREIGN KEY (signature_algorithm_id)
      REFERENCES algorithm (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS crl_generation_info
  OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS ca_crl_generation_info
(
  caentity_id bigint,
  crl_generation_info_id bigint,
  CONSTRAINT fk_caentity_id FOREIGN KEY (caentity_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_crlinfo_id FOREIGN KEY (crl_generation_info_id)
      REFERENCES crl_generation_info (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_crl_generation_info_id UNIQUE (crl_generation_info_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_crl_generation_info
  OWNER TO pkimanager;
  
CREATE TABLE IF NOT EXISTS crl_generation_info_ca_certificate
(
  crl_generation_info_id integer NOT NULL,
  certificate_id bigint NOT NULL,
  CONSTRAINT pk_crl_generation_info_ca_certificate_id PRIMARY KEY (crl_generation_info_id, certificate_id),
  CONSTRAINT fk_crl_generation_info_id FOREIGN KEY (crl_generation_info_id)
      REFERENCES crl_generation_info (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uc_certificate_id UNIQUE (certificate_id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS crl_generation_info_ca_certificate
  OWNER TO pkimanager;

---Scripts for crlgenerationinfo end-----------  

--Scripts added for crl--

SELECT create_sequence_if_not_exists('SEQ_CRL_ID','CREATE SEQUENCE SEQ_CRL_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CRL_ID OWNER TO pkimanager;


 CREATE TABLE IF NOT EXISTS crl
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CRL_ID'),
  crl bytea NOT NULL,
  CONSTRAINT pk_crl_id PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS crl
  OWNER TO pkimanager;
  
CREATE TABLE IF NOT EXISTS crl_status
(
  id integer NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_crl_status_id PRIMARY KEY (id),
  CONSTRAINT uk_crl_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS crl_status
  OWNER TO pkimanager;

SELECT create_sequence_if_not_exists('SEQ_CRLINFO_ID','CREATE SEQUENCE SEQ_CRLINFO_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CRLINFO_ID OWNER TO pkimanager;
  
 CREATE TABLE IF NOT EXISTS crlinfo
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CRLINFO_ID'),
  crl_number integer NOT NULL,
  this_update timestamp without time zone NOT NULL,
  next_update timestamp without time zone NOT NULL,
  status_id integer NOT NULL,
  certificate_id bigint,
  crl_id bigint,
  published_to_cdps boolean,
  CONSTRAINT pk_crlinfo_id PRIMARY KEY (id),
  CONSTRAINT fk_certificate_id FOREIGN KEY (certificate_id)
      REFERENCES certificate (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_crl_id FOREIGN KEY (crl_id)
      REFERENCES crl (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_status FOREIGN KEY (status_id)
      REFERENCES crl_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS crlinfo
  OWNER TO pkimanager;
  

  
CREATE TABLE IF NOT EXISTS ca_crlinfo
(
  ca_id bigint NOT NULL,
  crlinfo_id bigint NOT NULL,
  CONSTRAINT pk_ca_crlinfo_id PRIMARY KEY (ca_id, crlinfo_id),
  CONSTRAINT fk_crlinfo_id FOREIGN KEY (crlinfo_id)
      REFERENCES crlinfo (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_caentity_id FOREIGN KEY (ca_id)
      REFERENCES caentity (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_crlinfo
  OWNER TO pkimanager;