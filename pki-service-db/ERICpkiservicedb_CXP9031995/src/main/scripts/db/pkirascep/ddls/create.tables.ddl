CREATE TABLE IF NOT EXISTS sceprequest
(
  transaction_id CHARACTER VARYING(255) NOT NULL,
  subject_dn CHARACTER VARYING(255) NOT NULL,
  issuer_dn CHARACTER VARYING(255) NOT NULL,
  message_time TIMESTAMP NOT NULL,
  fail_info CHARACTER VARYING(255),
  status_id INTEGER NOT NULL,
  certificate BYTEA,
  CONSTRAINT pk_sceprequest_transaction_id PRIMARY KEY (transaction_id)
 )
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS sceprequest
  OWNER TO pkirascep;
 