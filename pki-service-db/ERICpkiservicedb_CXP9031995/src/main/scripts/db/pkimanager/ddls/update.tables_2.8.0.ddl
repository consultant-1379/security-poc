-- sequence for ca_configuration table
SELECT create_sequence_if_not_exists('seq_ca_config_id','CREATE SEQUENCE SEQ_CA_CONFIG_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CA_CONFIG_ID OWNER TO pkimanagergrp;

-- table to store caentity configuration details
CREATE TABLE IF NOT EXISTS ca_configuration
 (
  id bigint NOT NULL DEFAULT NEXTVAL('SEQ_CA_CONFIG_ID'),
  issue_certs_with_more_validity boolean,
  issuing_certs_validity_reduction_period integer,
  created_date timestamp without time zone,
  modified_date timestamp without time zone,
  CONSTRAINT pk_ca_configuration_id PRIMARY KEY (id)
  )
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS ca_configuration OWNER TO pkimanagergrp;

-- column ca_configuration to indicate to which ca configuration details belongs to.
SELECT add_column_if_not_exists('caentity', 'ca_configuration_id', 'ALTER TABLE IF EXISTS caentity ADD COLUMN ca_configuration_id bigint');

SELECT create_constraint_if_not_exists('ca_configuration','fk_caentity_ca_config_id','ALTER TABLE IF EXISTS caentity
       ADD CONSTRAINT fk_caentity_ca_config_id FOREIGN KEY (ca_configuration_id)
            REFERENCES ca_configuration (id) MATCH SIMPLE
            ON UPDATE NO ACTION ON DELETE NO ACTION');
