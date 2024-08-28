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


SELECT create_sequence_if_not_exists('seq_cmp_id','CREATE SEQUENCE SEQ_CMP_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CMP_ID OWNER TO pkiracmp;

CREATE TABLE IF NOT EXISTS cmpmessages
(
  serial_no INTEGER NOT NULL DEFAULT NEXTVAL('SEQ_CMP_ID'),
  create_time TIMESTAMP without TIME ZONE,
  initial_message BYTEA,
  modify_time TIMESTAMP without TIME ZONE,
  request_type CHARACTER VARYING(255),
  response_message BYTEA,
  sender_name CHARACTER VARYING(255),
  sender_nonce CHARACTER VARYING(255),
  status CHARACTER VARYING(255),
  transaction_id CHARACTER VARYING(255),
  CONSTRAINT pk_cmpmessages_serial_no PRIMARY KEY (serial_no)
) 
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS cmpmessages
  OWNER TO pkiracmp; 