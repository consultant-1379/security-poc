-- function for configuring CA certificate expiry notification details.

CREATE OR REPLACE FUNCTION configure_ca_cert_exp_not_details()
RETURNS void AS
$BODY$
DECLARE cid INTEGER;
BEGIN
FOR cid in (select ca.id from caentity ca where ca.is_external_ca=false)
LOOP
WITH cert_expiry_notification_dtls_critical AS (
INSERT INTO certificate_expiry_notification_details(id, notification_severity,period_before_expiry,frequency_of_notification,notification_message) SELECT nextval('SEQ_CERT_EXP_NOT_ID'),1,30,1,'Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.' WHERE NOT EXISTS (SELECT * FROM certificate_expiry_notification_details cert_exp_notify join ca_cert_exp_notification_details ca_cert_exp on cert_exp_notify.id=ca_cert_exp.ca_cert_exp_not_details_id 
WHERE cert_exp_notify.notification_severity = 1 and ca_cert_exp.ca_id= cid)
 RETURNING *
)
INSERT INTO ca_cert_exp_notification_details(ca_id,ca_cert_exp_not_details_id) SELECT cid, cert_expiry_notification_dtls_critical.id FROM cert_expiry_notification_dtls_critical WHERE NOT EXISTS (SELECT * FROM ca_cert_exp_notification_details ca_cert_exp_not, cert_expiry_notification_dtls_critical WHERE ca_cert_exp_not.ca_cert_exp_not_details_id = cert_expiry_notification_dtls_critical.id);

WITH cert_expiry_notification_dtls_major AS (
INSERT INTO certificate_expiry_notification_details(id, notification_severity,period_before_expiry,frequency_of_notification,notification_message) SELECT nextval('SEQ_CERT_EXP_NOT_ID'),2,60,2,'Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.' WHERE NOT EXISTS (SELECT * FROM certificate_expiry_notification_details cert_exp_notify join ca_cert_exp_notification_details ca_cert_exp on cert_exp_notify.id=ca_cert_exp.ca_cert_exp_not_details_id
WHERE cert_exp_notify.notification_severity = 2 and ca_cert_exp.ca_id= cid)
 RETURNING *
)
INSERT INTO ca_cert_exp_notification_details(ca_id,ca_cert_exp_not_details_id) SELECT cid,cert_expiry_notification_dtls_major.id FROM cert_expiry_notification_dtls_major WHERE NOT EXISTS (SELECT * FROM ca_cert_exp_notification_details ca_cert_exp_not, cert_expiry_notification_dtls_major WHERE ca_cert_exp_not.ca_cert_exp_not_details_id = cert_expiry_notification_dtls_major.id);

WITH cert_expiry_notification_dtls_warning AS (
INSERT INTO certificate_expiry_notification_details(id, notification_severity,period_before_expiry,frequency_of_notification,notification_message) SELECT nextval('SEQ_CERT_EXP_NOT_ID'),3,90,4,'Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.' WHERE NOT EXISTS (SELECT * FROM certificate_expiry_notification_details cert_exp_notify join ca_cert_exp_notification_details ca_cert_exp on cert_exp_notify.id=ca_cert_exp.ca_cert_exp_not_details_id
WHERE cert_exp_notify.notification_severity = 3 and ca_cert_exp.ca_id= cid)
 RETURNING *
)
INSERT INTO ca_cert_exp_notification_details(ca_id,ca_cert_exp_not_details_id) SELECT cid,cert_expiry_notification_dtls_warning.id FROM cert_expiry_notification_dtls_warning WHERE NOT EXISTS (SELECT * FROM ca_cert_exp_notification_details ca_cert_exp_not, cert_expiry_notification_dtls_warning WHERE ca_cert_exp_not.ca_cert_exp_not_details_id = cert_expiry_notification_dtls_warning.id);

WITH cert_expiry_notification_dtls_minor AS (
INSERT INTO certificate_expiry_notification_details(id, notification_severity,period_before_expiry,frequency_of_notification,notification_message) SELECT nextval('SEQ_CERT_EXP_NOT_ID'),4,180,7,'Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.' WHERE NOT EXISTS (SELECT * FROM certificate_expiry_notification_details cert_exp_notify join ca_cert_exp_notification_details ca_cert_exp on cert_exp_notify.id=ca_cert_exp.ca_cert_exp_not_details_id
WHERE cert_exp_notify.notification_severity = 4 and ca_cert_exp.ca_id= cid)
 RETURNING *
)
INSERT INTO ca_cert_exp_notification_details(ca_id,ca_cert_exp_not_details_id) SELECT cid,cert_expiry_notification_dtls_minor.id FROM cert_expiry_notification_dtls_minor WHERE NOT EXISTS (SELECT * FROM ca_cert_exp_notification_details ca_cert_exp_not, cert_expiry_notification_dtls_minor WHERE ca_cert_exp_not.ca_cert_exp_not_details_id = cert_expiry_notification_dtls_minor.id);
END LOOP;
END;
$BODY$
LANGUAGE plpgsql;