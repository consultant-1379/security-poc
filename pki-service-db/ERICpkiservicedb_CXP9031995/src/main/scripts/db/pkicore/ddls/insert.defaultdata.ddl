INSERT INTO algorithm_type(id, type) SELECT 1, 'MESSAGE_DIGEST_ALGORITHM' WHERE NOT EXISTS (SELECT * FROM algorithm_type WHERE id = 1 and type='MESSAGE_DIGEST_ALGORITHM');
INSERT INTO algorithm_type(id, type) SELECT 2, 'SIGNATURE_ALGORITHM' WHERE NOT EXISTS (SELECT * FROM algorithm_type WHERE id = 2 and type='SIGNATURE_ALGORITHM');
INSERT INTO algorithm_type(id, type) SELECT 3, 'ASYMMETRIC_KEY_ALGORITHM' WHERE NOT EXISTS (SELECT * FROM algorithm_type WHERE id = 3 and type='ASYMMETRIC_KEY_ALGORITHM');
INSERT INTO algorithm_type(id, type) SELECT 4, 'SYMMETRIC_KEY_ALGORITHM' WHERE NOT EXISTS (SELECT * FROM algorithm_type WHERE id = 4 and type='SYMMETRIC_KEY_ALGORITHM');

INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 1,NULL, 'SHA1withRSA', '1.2.840.113549.1.1.5', FALSE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA1withRSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 2,NULL, 'MD5withRSA', '1.3.14.3.2.3', FALSE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'MD5withRSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 3,NULL, 'SHA256withRSA', '1.2.840.113549.1.1.11', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA256withRSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 4,NULL, 'SHA512withRSA', '1.2.840.113549.1.1.13', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA512withRSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 5,NULL, 'SHA1withDSA', '1.2.840.10040.4.3', FALSE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA1withDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 6,NULL, 'SHA256withDSA', '2.16.840.1.101.3.4.3.2', FALSE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA256withDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 7,NULL, 'SHA512withDSA', '', FALSE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA512withDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 8,NULL, 'SHA256withECDSA', '1.2.840.10045.4.3.2', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA256withECDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 9,NULL, 'SHA384withECDSA', '1.2.840.10045.4.3.3', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA384withECDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 10,NULL, 'SHA512withECDSA', '1.2.840.10045.4.3.4', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA512withECDSA');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 11,NULL, 'SHA224', '2.16.840.1.101.3.4.2.4', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA224');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 12,NULL, 'SHA256', '2.16.840.1.101.3.4.2.1', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA256');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 13,NULL, 'SHA384', '2.16.840.1.101.3.4.2.2', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA384');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 14,NULL, 'SHA512', '2.16.840.1.101.3.4.2.3', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA512');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 15,NULL, 'SHA1', '1.3.14.3.2.26', FALSE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA1');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 16,NULL, 'SHA3-224', '2.16.840.1.101.3.4.2.7', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA3-224');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 17,NULL, 'SHA3-256', '2.16.840.1.101.3.4.2.8', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA3-256');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 18,NULL, 'SHA3-384', '2.16.840.1.101.3.4.2.9', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA3-384');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 19,NULL, 'SHA3-512', '2.16.840.1.101.3.4.2.10', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'SHA3-512');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 20,NULL, 'MD5', '1.2.840.113549.2.5', FALSE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'MD5');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 21,1024, 'RSA', '1.2.840.113549.1.1.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'RSA' and key_size=1024);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 22,2048, 'RSA', '1.2.840.113549.1.1.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'RSA' and key_size=2048);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 23,3072, 'RSA', '1.2.840.113549.1.1.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'RSA' and key_size=3072);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 24,4096, 'RSA', '1.2.840.113549.1.1.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'RSA' and key_size=4096);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 25,1024, 'DSA', '1.3.14.3.2.12', FALSE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DSA' and key_size=1024);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 26,160, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=160);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 27,163, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=163);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 28,224, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=224);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 29,256, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=256);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 30,283, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=283);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 31,384, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=384);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 32,409, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=409);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 33,512, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=512);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 34,571, 'ECDSA', '2.23.42.9.11.4.1', TRUE, 3 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'ECDSA' and key_size=571);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 35,64 , 'DES_ECB', '1.3.14.3.2.6', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES_ECB' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 36,64 , 'DES_CBC', '1.3.14.3.2.7', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES_CBC' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 37,64 , 'DES_OFB', '1.3.14.3.2.8', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES_OFB' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 38,64 , 'DES_CFB', '1.3.14.3.2.9', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES_CFB' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 39,64 , 'DES_EDE', '1.3.14.3.2.17', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES_EDE' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 40,64 , '3DES', '1.3.6.1.4.1.4929.1.6', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = '3DES' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 41,64 , 'DES-EDE3-CBC', '1.2.840.113549.3.7', TRUE, 4 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'DES-EDE3-CBC' and key_size=64);
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 42,NULL , 'HMAC_SHA1', '1.3.6.1.5.5.8.1.2', FALSE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'HMAC_SHA1');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 43,NULL , 'HMAC_SHA256', '1.2.840.113549.2.9', TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'HMAC_SHA256');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 44,NULL , '160-BIT_SHA-1', NULL, TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = '160-BIT_SHA-1');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 45,NULL , '0100-60-BIT_SHA-1', NULL, TRUE, 1 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = '0100-60-BIT_SHA-1');
INSERT INTO algorithm(id,key_size, name, oid, is_supported, type_id) SELECT 46,NULL, 'PasswordBasedMAC', '1.2.840.113533.7.66.13', TRUE, 2 WHERE NOT EXISTS (SELECT * FROM algorithm WHERE name = 'PasswordBasedMAC');


INSERT INTO entity_status(id, status_name) SELECT 1, 'NEW' WHERE NOT EXISTS (SELECT * FROM entity_status WHERE id = 1 and status_name='NEW');
INSERT INTO entity_status(id, status_name) SELECT 2, 'ACTIVE' WHERE NOT EXISTS (SELECT * FROM entity_status WHERE id = 2 and status_name='ACTIVE');
INSERT INTO entity_status(id, status_name) SELECT 3, 'INACTIVE' WHERE NOT EXISTS (SELECT * FROM entity_status WHERE id = 3 and status_name='INACTIVE');
INSERT INTO entity_status(id, status_name) SELECT 4, 'REISSUE' WHERE NOT EXISTS (SELECT * FROM entity_status WHERE id = 4 and status_name='REISSUE');
INSERT INTO entity_status(id, status_name) SELECT 5, 'DELETED' WHERE NOT EXISTS (SELECT * FROM entity_status WHERE id = 5 and status_name='DELETED');

INSERT INTO certificate_status(id, status_name) SELECT 1, 'ACTIVE' WHERE NOT EXISTS (SELECT * FROM certificate_status WHERE id = 1 and status_name='ACTIVE');
INSERT INTO certificate_status(id, status_name) SELECT 2, 'EXPIRED' WHERE NOT EXISTS (SELECT * FROM certificate_status WHERE id = 2 and status_name='EXPIRED');
INSERT INTO certificate_status(id, status_name) SELECT 3, 'REVOKED' WHERE NOT EXISTS (SELECT * FROM certificate_status WHERE id = 3 and status_name='REVOKED');
INSERT INTO certificate_status(id, status_name) SELECT 4, 'INACTIVE' WHERE NOT EXISTS (SELECT * FROM certificate_status WHERE id = 4 and status_name='INACTIVE');

INSERT INTO ca_status(id, status_name) SELECT 1, 'NEW' WHERE NOT EXISTS (SELECT * FROM ca_status WHERE Id = 1 and status_name='NEW');
INSERT INTO ca_status(id, status_name) SELECT 2, 'ACTIVE' WHERE NOT EXISTS (SELECT * FROM ca_status WHERE Id = 2 and status_name='ACTIVE');
INSERT INTO ca_status(id, status_name) SELECT 3, 'INACTIVE' WHERE NOT EXISTS (SELECT * FROM ca_status WHERE Id = 3 and status_name='INACTIVE');
INSERT INTO ca_status(id, status_name) SELECT 4, 'DELETED' WHERE NOT EXISTS (SELECT * FROM ca_status WHERE Id = 4 and status_name='DELETED');

INSERT INTO certificate_request_status(id, status_name) SELECT 1, 'NEW' WHERE NOT EXISTS (SELECT * FROM certificate_request_status WHERE id = 1 and status_name='NEW');
INSERT INTO certificate_request_status(id, status_name) SELECT 2, 'ISSUED' WHERE NOT EXISTS (SELECT * FROM certificate_request_status WHERE id = 2 and status_name='ISSUED');
INSERT INTO certificate_request_status(id, status_name) SELECT 3, 'FAILED' WHERE NOT EXISTS (SELECT * FROM certificate_request_status WHERE id = 3 and status_name='FAILED');

INSERT INTO keypair_status(id, status_name) SELECT 1, 'ACTIVE' WHERE NOT EXISTS (SELECT * FROM keypair_status WHERE id = 1 and status_name='ACTIVE');
INSERT INTO keypair_status(id, status_name) SELECT 2, 'INACTIVE' WHERE NOT EXISTS (SELECT * FROM keypair_status WHERE id = 2 and status_name='INACTIVE');

INSERT INTO request_type(id, type) SELECT 1, 'NEW' WHERE NOT EXISTS (SELECT * FROM request_type WHERE id = 1 and type='NEW');
INSERT INTO request_type(id, type) SELECT 2, 'RENEW' WHERE NOT EXISTS (SELECT * FROM request_type WHERE id = 2 and type='RENEW');
INSERT INTO request_type(id, type) SELECT 3, 'MODIFY' WHERE NOT EXISTS (SELECT * FROM request_type WHERE id = 3 and type='MODIFY');
INSERT INTO request_type(id, type) SELECT 4, 'REKEY' WHERE NOT EXISTS (SELECT * FROM request_type WHERE id = 4 and type='REKEY');

INSERT INTO certificate_version(id, version) SELECT 2, 'V3' WHERE NOT EXISTS (SELECT * FROM certificate_version WHERE id = 2 and version='V3');

INSERT INTO algorithmcategory(id, category_name) SELECT 1, 'OTHER' WHERE NOT EXISTS (SELECT * FROM algorithmcategory WHERE id = 1 and category_name='OTHER');
INSERT INTO algorithmcategory(id, category_name) SELECT 2, 'KEY_IDENTIFIER' WHERE NOT EXISTS (SELECT * FROM algorithmcategory WHERE id = 2 and category_name='KEY_IDENTIFIER');


INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 1, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 1);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 2, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 2);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 3, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 3);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 4, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 4);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 5, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 5);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 6, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 6);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 7, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 7);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 8, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 8);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 9, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 9);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 10, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 10);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 11, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 11);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 12, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 12);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 13, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 13);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 14, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 14);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 15, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 15);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 16, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 16);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 17, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 17);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 18, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 18);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 19, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 19);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 20, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 20);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 21, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 21);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 22, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 22);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 23, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 23);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 24, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 24);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 25, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 25);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 26, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 26);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 27, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 27);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 28, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 28);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 29, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 29);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 30, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 30);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 31, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 31);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 32, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 32);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 33, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 33);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 34, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 34);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 35, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 35);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 36, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 36);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 37, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 37);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 38, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 38);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 39, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 39);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 40, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 40);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 41, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 41);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 42, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 42);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 43, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 43);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 44, 2 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 44);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 45, 2 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 45);
INSERT INTO algorithm_algorithmcategory(algorithm_id,category_id) SELECT 46, 1 WHERE NOT EXISTS (SELECT * FROM algorithm_algorithmcategory WHERE algorithm_id = 46);

