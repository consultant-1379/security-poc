-- update certificate categories
begin;
update certificate set certificate_category = (select cert_cat.id from certificate_category cert_cat where cert_cat.type='INTERNAL_CA') where id in (select ca_cert.certificate_id from certificate_authority ca join ca_certificate ca_cert on ca_cert.ca_id=ca.id );
update certificate set certificate_category = (select cert_cat.id from certificate_category cert_cat where cert_cat.type='ENTITY') where certificate_category IS NULL;
commit;