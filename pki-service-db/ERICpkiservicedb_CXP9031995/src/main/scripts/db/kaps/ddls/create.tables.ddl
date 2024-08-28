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

SELECT create_sequence_if_not_exists('seq_encrypted_privatekey_info_id','CREATE SEQUENCE SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID OWNER TO kaps;

CREATE TABLE encrypted_privatekey_info
(
  id bigint NOT NULL DEFAULT nextval('SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID'::regclass),
  privatekey bytea NOT NULL,
  privatekey_hash bytea NOT NULL,
  CONSTRAINT pk_encrypted_privatekey_info_id PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE encrypted_privatekey_info
  OWNER TO kaps;


CREATE TABLE keypair_status
(
  id bigint NOT NULL,
  status_name character varying(255) NOT NULL,
  CONSTRAINT pk_keypair_status_id PRIMARY KEY (id),
  CONSTRAINT uc_keypair_status_id UNIQUE (status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE keypair_status
  OWNER TO kaps;
  

SELECT create_sequence_if_not_exists('seq_key_identifier_id','CREATE SEQUENCE SEQ_KEY_IDENTIFIER_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_KEY_IDENTIFIER_ID OWNER TO kaps;


SELECT create_sequence_if_not_exists('seq_keypair_info_id','CREATE SEQUENCE SEQ_KEYPAIR_INFO_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_KEYPAIR_INFO_ID OWNER TO kaps;

CREATE TABLE keypair_info
(
  id bigint NOT NULL DEFAULT nextval('SEQ_KEYPAIR_INFO_ID'::regclass),
  keyidentifier character varying(255) NOT NULL,
  publickey bytea NOT NULL,
  algorithm character varying(255) NOT NULL,
  keysize integer NOT NULL,
  createdtime date NOT NULL,
  updatedtime date,
  status_id bigint NOT NULL,
  encrypted_privatekey_info_id bigint NOT NULL,
  CONSTRAINT pk_keypair_info_id PRIMARY KEY (id),
  CONSTRAINT uc_key_identifier_id UNIQUE (keyidentifier),
  CONSTRAINT fk_keypair_info_encrypted_privatekey_info_id FOREIGN KEY (encrypted_privatekey_info_id)
      REFERENCES encrypted_privatekey_info (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_keypair_info_keypair_status_id FOREIGN KEY (status_id)
      REFERENCES keypair_status (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);

ALTER TABLE IF EXISTS keypair_info OWNER TO kaps;


SELECT create_sequence_if_not_exists('seq_symmetric_key_id','CREATE SEQUENCE SEQ_SYMMETRIC_KEY_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_SYMMETRIC_KEY_ID OWNER TO kaps;

CREATE TABLE IF NOT EXISTS symmetric_key
(
  id bigint NOT NULL DEFAULT nextval('SEQ_SYMMETRIC_KEY_ID'::regclass),
  symmetrickey bytea NOT NULL,
  CONSTRAINT pk_symmetric_key_id PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE  IF EXISTS symmetric_key
  OWNER TO kaps;