CREATE OR REPLACE FUNCTION reorder_subject_dn()
RETURNS void AS
$BODY$
BEGIN

	UPDATE entity SET NAME_ALIAS=( select lower(name));
	UPDATE entity SET
	subject_dn = rtrim(substring(concat(
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(CN=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(SURNAME=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(C=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(L=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(ST=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(STREET=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(O=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(OU=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(DN=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),',\s*(T=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'^\s*(T=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(GIVENNAME=.*?,).*'))),
	(select unnest (regexp_matches((concat(subject_dn,',') ),'(SN=.*?,).*')))
	),1,char_length(subject_dn)),',');

	CREATE EXTENSION IF NOT EXISTS pgcrypto;

	UPDATE subject_identification_details SET subject_dn_hash = digest(lower(entity.subject_dn), 'sha256') FROM entity
	WHERE entity.id = subject_identification_details.entity_id
	AND NOT digest(lower(entity.subject_dn), 'sha256') = subject_identification_details.subject_dn_hash;

	INSERT INTO subject_identification_details(entity_id, subject_dn_hash)
	SELECT id,digest(lower(subject_dn), 'sha256') from entity
	WHERE NOT EXISTS (SELECT * FROM subject_identification_details WHERE entity.id = subject_identification_details.entity_id);

	EXCEPTION WHEN OTHERS THEN
		RAISE EXCEPTION 'EXCEPTION OCCURED WHILE RE-ORDERING AND HASHING THE SUBJECT DN';
		RAISE SQLSTATE 'P0001';
END;
$BODY$
LANGUAGE 'plpgsql';


BEGIN;
	LOCK TABLE entity IN ACCESS EXCLUSIVE MODE;
	SELECT reorder_subject_dn();
COMMIT;