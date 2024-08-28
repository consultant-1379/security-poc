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

SELECT create_sequence_if_not_exists('seq_algorithm_id','CREATE SEQUENCE SEQ_ALGORITHM_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ALGORITHM_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS Algorithm
(
  Id INTEGER NOT NULL DEFAULT NEXTVAL('SEQ_ALGORITHM_ID'),
  Key_Size INTEGER,
  Name CHARACTER VARYING(255) NOT NULL,
  Oid CHARACTER VARYING(255),
  Is_Supported BOOLEAN NOT NULL,
  Type CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_Algorithm_Id PRIMARY KEY (Id),
  CONSTRAINT uk_Algorithm_Name_Key_Size UNIQUE (Name, Key_Size)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Algorithm
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS Entity_Status
(
  Id INTEGER NOT NULL,
  Status_Name CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_Entity_Status_Id PRIMARY KEY (Id),
  CONSTRAINT uk_Entity_Status_Name UNIQUE (Status_Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Entity_Status
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS Certificate_Status
(
  Id INTEGER NOT NULL,
  Status_name CHARACTER VARYING(255) NOT NULL,
  CONSTRAINT pk_Certificate_Status_Id PRIMARY KEY (Id),
  CONSTRAINT uk_Certificate_Status_name UNIQUE (Status_name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Certificate_Status
  OWNER TO pkimanager;


SELECT create_sequence_if_not_exists('seq_profile_id','CREATE SEQUENCE SEQ_PROFILE_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_PROFILE_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS TrustProfile
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  Is_Active BOOLEAN NOT NULL,
  Name CHARACTER VARYING(255) NOT NULL,
  Profile_Validity TIMESTAMP WITHOUT TIME ZONE,
  CONSTRAINT pk_TrustProfile_Id PRIMARY KEY (Id),
  CONSTRAINT uk_TrustProfile_Name UNIQUE (Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS TrustProfile
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS EntityProfile
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  Is_Active BOOLEAN NOT NULL,
  Name CHARACTER VARYING(255) NOT NULL,
  Profile_Validity TIMESTAMP WITHOUT TIME ZONE,
  Certificate_Extensions TEXT,
  Subject_Alt_Name TEXT,
  Subject_DN TEXT,
  Certificate_Profile_Id BIGINT NOT NULL,
  Key_Generation_Algorithm_Id INTEGER,
  CONSTRAINT pk_EntityProfile_Id PRIMARY KEY (Id),
  CONSTRAINT fk_EntityProfile_Algorithm FOREIGN KEY (Key_Generation_Algorithm_Id)
      REFERENCES Algorithm (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_EntityProfile_Name UNIQUE (Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS EntityProfile
  OWNER TO pkimanager;


SELECT create_sequence_if_not_exists('seq_ca_id','CREATE SEQUENCE SEQ_CA_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CA_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS CAEntity
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_CA_ID'),
  Status_Id INTEGER NOT NULL,
  Is_CSR_Generated BOOLEAN NOT NULL,
  Name CHARACTER VARYING(255) NOT NULL,
  PublishCertificateToTDPS BOOLEAN NOT NULL,
  Is_Root_CA BOOLEAN NOT NULL,
  Subject_Alt_Name TEXT,
  Subject_DN TEXT,
  Entity_Profile_Id BIGINT NOT NULL,
  Key_Generation_Algorithm_Id INTEGER,
  CONSTRAINT pk_CAEntity_Id PRIMARY KEY (Id),
  CONSTRAINT fk_CAEntity_EntityProfile FOREIGN KEY (Entity_Profile_Id)
      REFERENCES EntityProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_CAEntity_Algorithm FOREIGN KEY (Key_Generation_Algorithm_Id)
      REFERENCES Algorithm (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_CAEntity_Status_Id FOREIGN KEY (Status_Id)
      REFERENCES Entity_Status (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_CAEntity_Name UNIQUE (Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS CAEntity
  OWNER TO pkimanager;



CREATE TABLE IF NOT EXISTS CertificateProfile
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_PROFILE_ID'),
  Is_Active BOOLEAN NOT NULL,
  Name CHARACTER VARYING(255) NOT NULL,
  Profile_Validity TIMESTAMP WITHOUT TIME ZONE,
  Certificate_Extensions TEXT,
  For_CA_Entity BOOLEAN NOT NULL,
  Issuer_Unique_Identifier BOOLEAN NOT NULL,
  Skew_Certificate_Time CHARACTER VARYING(10),
  Subject_Unique_Identifier BOOLEAN NOT NULL,
  Validity CHARACTER VARYING(10) NOT NULL,
  Version CHARACTER VARYING(255) NOT NULL,
  Issuer_Id BIGINT,
  Signature_Algorithm_Id INTEGER NOT NULL,
  CONSTRAINT pk_CertificateProfile_Id PRIMARY KEY (Id),
  CONSTRAINT fk_CertificateProfile_Issuer_Id FOREIGN KEY (Issuer_Id)
      REFERENCES CAEntity (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_CertificateProfile_Algorithm FOREIGN KEY (Signature_Algorithm_Id)
      REFERENCES Algorithm (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_CertificateProfile_Name UNIQUE (Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS CertificateProfile
  OWNER TO pkimanager;

SELECT create_constraint_if_not_exists('certificateprofile','fk_certificate_profile_id','ALTER TABLE IF EXISTS EntityProfile
ADD CONSTRAINT fk_Certificate_Profile_Id FOREIGN KEY (Certificate_Profile_Id)
REFERENCES CertificateProfile (Id) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION');

SELECT create_sequence_if_not_exists('seq_entity_id','CREATE SEQUENCE SEQ_ENTITY_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_ENTITY_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS Entity
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_ENTITY_ID'),
  Status_Id integer NOT NULL,
  Name CHARACTER VARYING(255) NOT NULL,
  Subject_Alt_Name TEXT,
  Subject_DN TEXT,
  Otp CHARACTER VARYING(255),
  Otp_Count INTEGER,
  PublishCertificateToTDPS boolean NOT NULL,
  Entity_Profile_Id BIGINT NOT NULL,
  Key_Generation_Algorithm_Id INTEGER,
  CONSTRAINT pk_Entity_Id PRIMARY KEY (Id),
  CONSTRAINT fk_Entity_Algorithm FOREIGN KEY (Key_Generation_Algorithm_Id)
      REFERENCES Algorithm (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_Entity_EntityProfile FOREIGN KEY (Entity_Profile_Id)
      REFERENCES EntityProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_Entity_Status_Id FOREIGN KEY (Status_Id)
      REFERENCES Entity_Status (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_Entity_Name UNIQUE (Name)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Entity
  OWNER TO pkimanager;


SELECT create_sequence_if_not_exists('seq_certificate_id','CREATE SEQUENCE SEQ_CERTIFICATE_ID START 1');
ALTER SEQUENCE IF EXISTS SEQ_CERTIFICATE_ID OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS Certificate_Data
(
  Id BIGINT NOT NULL DEFAULT NEXTVAL('SEQ_CERTIFICATE_ID'),
  Certificate BYTEA NOT NULL,
  Issued_Time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  Not_After TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  Not_Before TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  Serial_Number CHARACTER VARYING(255) NOT NULL,
  Status_Id INTEGER NOT NULL,
  CONSTRAINT pk_Certificate_Id PRIMARY KEY (Id),
  CONSTRAINT fk_Certificate_Status_Id FOREIGN KEY (Status_Id)
      REFERENCES Certificate_Status (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Certificate_Data
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS CertificateProfile_KeyGenerationAlgorithm
(
  Certificate_Profile_Id BIGINT NOT NULL,
  Key_Generation_Algorithm_Id INTEGER NOT NULL,
  CONSTRAINT pk_Certificate_Profile_Id_Key_Generation_Algorithm_Id PRIMARY KEY (Certificate_Profile_Id, Key_Generation_Algorithm_Id),
  CONSTRAINT fk_CertificateProfile_KeyGenerationAlgorithm_Algorithm FOREIGN KEY (Key_Generation_Algorithm_Id)
      REFERENCES Algorithm (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_CertificateProfile_KeyGenerationAlgorithm_CertificateProfile FOREIGN KEY (Certificate_Profile_Id)
      REFERENCES CertificateProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS CertificateProfile_KeyGenerationAlgorithm
  OWNER TO pkimanager;

CREATE TABLE IF NOT EXISTS EntityProfile_TrustProfile
(
  Entity_Profile_Id BIGINT NOT NULL,
  Trust_Profile_Id BIGINT NOT NULL,
  CONSTRAINT pk_Entity_Profile_Id_Trust_Profile_Id PRIMARY KEY (Entity_Profile_Id, Trust_Profile_Id),
  CONSTRAINT fk_EntityProfile_Entity_Profile_Id FOREIGN KEY (Entity_Profile_Id)
      REFERENCES EntityProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_TrustProfile_Trust_Profile_Id FOREIGN KEY (Trust_Profile_Id)
      REFERENCES TrustProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS EntityProfile_TrustProfile
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS TrustProfile_InternalCA
(
  Trust_Profile_Id BIGINT NOT NULL,
  InternalCA_Id BIGINT NOT NULL,
  CONSTRAINT pk_Trust_Profile_Id_InternalCA_Id PRIMARY KEY (Trust_Profile_Id, InternalCA_Id),
  CONSTRAINT fk_CAEntity_InternalCA_Id FOREIGN KEY (InternalCA_Id)
      REFERENCES CAEntity (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_TrustProfile_InternalCA_Trust_Profile_Id FOREIGN KEY (Trust_Profile_Id)
      REFERENCES TrustProfile (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS TrustProfile_InternalCA
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS CA_Certificate
(
  CA_Id BIGINT NOT NULL,
  Certificate_Id BIGINT NOT NULL,
  CONSTRAINT pk_CA_Id_Certificate_Id PRIMARY KEY (CA_Id, Certificate_Id),
  CONSTRAINT fk_CAEntity_CA_Id FOREIGN KEY (CA_Id)
      REFERENCES CAEntity (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_Certificate_Data_Certificate_Id FOREIGN KEY (Certificate_Id)
      REFERENCES Certificate_Data (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_CA_Certificate_Certificate_Id UNIQUE (Certificate_Id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS CA_Certificate
  OWNER TO pkimanager;


CREATE TABLE IF NOT EXISTS Entity_Certificate
(
  Entity_Id BIGINT NOT NULL,
  Certificate_Id BIGINT NOT NULL,
  CONSTRAINT pk_Entity_Id_Certificate_Id PRIMARY KEY (Entity_Id, Certificate_Id),
  CONSTRAINT fk_Entity_Certificate_Certificate_Id FOREIGN KEY (Certificate_Id)
      REFERENCES Certificate_Data (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT fk_Entity_Entity_Id FOREIGN KEY (Entity_Id)
      REFERENCES Entity (Id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT uk_Entity_Certificate_Certificate_Id UNIQUE (Certificate_Id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE IF EXISTS Entity_Certificate
  OWNER TO pkimanager;
