SELECT create_sequence_if_not_exists('seq_custom_configuration_id','CREATE SEQUENCE SEQ_CUSTOM_CONFIGURATION_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CUSTOM_CONFIGURATION_ID OWNER TO pkimanagergrp;

CREATE TABLE IF NOT EXISTS custom_configuration
(
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CUSTOM_CONFIGURATION_ID'),
  name text NOT NULL,
  value text,
  note character varying(255),
  owner text NOT NULL,
  created_date timestamp without time zone  NOT NULL DEFAULT now(),
  modified_date timestamp without time zone  NOT NULL DEFAULT now(),
  CONSTRAINT pk_custom_configuration_id PRIMARY KEY (id),
  CONSTRAINT uk_custom_configuration_name_owner UNIQUE (name, owner)

)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS custom_configuration
  OWNER TO pkimanagergrp;
