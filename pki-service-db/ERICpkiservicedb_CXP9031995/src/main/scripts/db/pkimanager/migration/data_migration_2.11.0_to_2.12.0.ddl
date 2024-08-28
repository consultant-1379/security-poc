-- function for populating default expiry notification details of newly created CAs from dbversion 2.7.0 in certificate_expiry_notification_details.

begin;
select configure_ca_cert_exp_not_details();
commit;