/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.codes;

/**
 * Class for representing error messages common across all modules
 * 
 * @author
 */
public class ErrorMessages {

    // Common Error Messages
    public static final String ALGORITHM_NOT_FOUND = "Unable to find algorithm!";
    public static final String ALGORITHMTYPES_SHOULDNOTBENULL = "Algorithm Types Should not be null";
    public static final String CA_ENTITY_NOT_FOUND = "CAEntity not found";
    public static final String ENTITY_ALREADY_EXISTS = "Entity already exists";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate not found";
    public static final String ENTITY_CERTIFICATES_NOT_FOUND = "Certificates with the given End entity Name not found";
    public static final String CA_CERTIFICATES_NOT_FOUND = "Certificates with the given CA entity Name not found";
    public static final String CA_CERTIFICATE_NOT_FOUND = "No certificate found for CAEntity";
    public static final String ISSUERDN_SERIALNUMBER_MANDATORY = "IssuerDN and/or Serial Number is mandatory for List Issued Certificates";
    public static final String SUBJECTDN_ISSUERDN_SERIALNUMBER_MANDATORY = "SubjectDN and/or IssuerDN and/or SerialNumber is Mandatory for List Issued Certificates";
    public static final String SUBJECTDN_SERIALNUMBER_MANDATORY = "SubjectDN and/or SerialNumber is Mandatory for List Issued Certificates";
    public static final String CANAME_SERIALNUMBER_MANDATORY = "CAName and/or SerialNumber is Mandatory for List Issued Certificates";
    public static final String CERTIFICATE_STATUS_MANDATORY = "Certificate Status is Mandatory for List Issued Certificates";
    public static final String SUBJECTDN_MANDATORY = "SubjectDN is mandatory for List Issued Certificates";
    public static final String SERIALNUMBER_MANDATORY_LIST_ISSUED_CERTIFICATES = "SerialNumber is Mandatory for List Issued Certificates";
    public static final String CA_ENTITY_NOT_FOUND_SUBJECTDN = "CAEntity not found with SubjectDN/IssuerDN";
    public static final String CRL_NOT_FOUND = "No crl found";
    public static final String CONFIGURATION_PROPERTY_NOT_FOUND = "Configuration Property Not found";
    public static final String CONFIGURATION_PROPERTY_VALUE_NULL = "Configuration Property Value is null";
    public static final String FAIL_TO_UNPUBLISH_CRL = "Failure in unpublishing the crl for CA certificate";
    public static final String FAIL_TO_PUBLISH_CRL = "Failure in publishing the crl for CA certificate";
    public static final String INTERNAL_ERROR = "Exception occured while processing the request ";
    public static final String ERROR_OCCURED_IN_UPDATING_DATABASE = "Error occured in updating the database entity";
    public static final String AUTOMATIC_FETCH_LATEST_CRL_JOB_FAILED = "Automatic fetch latest CRL job failed ";
    public static final String AUTOMATIC_FETCH_EXTERNAL_CA_CRL_JOB_FAILED = "Automatic fetch external CA CRL job failed ";
    public static final String UPDATE_LATEST_CRL_FAILED = "Failed to update latest CRL in pki-manager data base ";
    public static final String AUTOMATIC_STATUS_UPDATE_JOB_FAILED = "Automatic status update job failed ";
    public static final String AUTOMATIC_PKI_CREDEM_MGMT_JOB_FAILED = "Automatic pki credentials management job failed due to :";
    public static final String FAILED_TO_RECREATE_TIMER = "Failed to recreate timer for the changed configuration parameter ";
    public static final String CERT_EXPIRY_NOTIFICATION_JOB_FAILED = "Exception occured while running certificate expiry notification job ";
    public static final String UNSUPPORTED_CHARACTERS_SUBJECT = "Subject field contains unsupported characters \\=,/\"";
    public static final String UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT = "Subject field contains unsupported characters \\=/\"";
    public static final String UNSUPPORTED_CHARACTERS_FOR_CSR_DIRECTORY_STRING_SUBJECT = "Subject field value in CSR contains unsupported characters \\=/\"";
    public static final String UNSUPPORTED_CHARACTERS_CSR_SUBJECT = "Subject field value in CSR contains unsupported characters \\=,/\"";
    public static final String ERROR_OCCURED_IN_GETTING_ISSUER_CERTIFICATE = "Exception occured while getting Issuer Certificate";

    // Error Messages for Entity Category
    public static final String INVALID_NAME_FORMAT = "Invalid Name Format!";
    public static final String REQUIRED_ENTITY_CATEGORY = "Entity category should be specified!";
    public static final String NO_ENTITY_CATEGORY_FOUND_WITH_ID = "No entity category found with ID: ";
    public static final String OCCURED_IN_CREATING_ENTITY_CATEGORY = " Occured in Creating Entity Category!";
    public static final String OCCURED_IN_UPDATING_ENTITY_CATEGORY = " Occured in Updating Entity Category!";
    public static final String OCCURED_IN_RETRIEVING_ENTITY_CATEGORY = " Occured in Retrieving Entity Category!";
    public static final String ERROR_OCCURED_WHILE_DELETING_ENTITY_CATEGORY = "Error Occured while deleting Entity Category!";
    public static final String NO_ENTITY_CATEGORY_FOUND_WITH_NAME = "No entity category found with Name: ";
    public static final String NO_ENTITY_CATEGORY_FOUND_WITH_ID_AND_NAME = "No entity category found with given id and name: ";
    public static final String ENTITY_PROFILE_IN_USE = "Entity category is being used by Entity Profiles : ";
    public static final String ENTITY_CATEGORY_EXISTS_ALREADY = "Entity Category Exists Already!";
    public static final String NO_ENTITIES_FOUND_WITH_CATEGORY = "No entities found with entity category: ";
    public static final String TRANSACTION_INACTIVE = "Transaction InActive!";
    public static final String ID_OR_NAME_SHOULD_PRESENT = "At least id or name should be specified!";
    public static final String CANNOT_UPDATE_ENTITY_CATEGORY = "Entity category cannot be updated";
    public static final String ENTITY_CATEGORY_IN_USE_BY_ENTTIY = "Entity category is being used by Entity and Entity Profiles : ";

    // Error Messages for CRL Management
    public static final String REVOKED_CERTIFICATE = "The certificate is revoked";
    public static final String EXPIRED_CERTIFICATE = "The certificate is expired";
    public static final String EXPIRED_OR_NOT_YET_VALID_CERTIFICATE = "The certificate is expired or not yet valid";
    public static final String NO_LATEST_CRL = "Latest CRL not found";
    public static final String ERROR_WHILE_GENERATING_CRL_FROM_GETCRL = "Invalid CRLGenerationInfo to generate CRL from getCrl when no CRL is found";
    public static final String NO_VALID_CERTIFICATE = "No valid Certificate found";
    public static final String EXPIRED_CERTIFICATE_STATUS = "Expired certificate status is not valid to process this request";
    public static final String REVOKED_CERTIFICATE_STATUS = "Revoked certificate status is not valid to process this request";
    public static final String UNABLE_TO_DELETE_INVALID_CRL = "Unable to delete invalid CRL for the %s due to %s";
    public static final String UNABLE_TO_FETCH_LATEST_CRL = "Unable to fetch latest CRL for the CA %s due to %s";

    // Error Messages for Revocation
    public static final String ROOT_CA_CANNOT_BE_REVOKED = "Root CA can not be revoked";
    public static final String SUBJECTDN_ISSUERDN_NOT_FOUND = "The certificate with given subject and issuerdn is not found ";
    public static final String INVALID_CERTIFICATE = "Invalid certificate";
    public static final String CERTIFICATE_ALREADY_REVOKED = "Certificate already revoked";
    public static final String ISSUER_CERTIFICATE_ALREADY_REVOKED = "Invalid Certificate chain. One of the certificates in chain is revoked. ";
    public static final String CERTIFICATE_CONVERSION_ERROR = "Problem with certificate converter";
    public static final String INVALID_INVALIDITY_DATE = "Invalidity date should be with in the range of certificate validity";
    public static final String ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED = "Root CA cannot be revoked. Root CA is Sub CA of External CA. Please contact external CA administrator for revocation of this Root CA";
    public static final String ROOT_CA_REISSUE_WITH_REVOCATION_NOT_SUPPORTED = "Root CA does not support reissue with revocation option as root ca certificate is a self signed certificate";

    // Error Messages for Certificate Management
    public static final String CERTIFICATE_ENCODING_FAILED = "Exception occured while encoding the certificate";
    public static final String CERTIFICATE_EXISTS = "CA already has an ACTIVE certificate";
    public static final String CERTIFICATE_GENERATION_FAILED = "Certificate Generation Failed";
    public static final String CERTIFICATE_STORAGE_FAILED = "Exception occured while saving the certificate";
    public static final String UNEXPECTED_ERROR = "Unexpected System Error";
    public static final String CERTIFCATE_DOWNLOAD_FAILED= "Download of Certificates is failed";
    public static final String CA_ACTIVE_CERTIFICATE_NOT_FOUND = "No ACTIVE certificate found for CAEntity";
    public static final String ACTIVE_CERTIFICATE_NOT_FOUND = "No ACTIVE certificate found";
    public static final String ENTITY_ACTIVE_CERTIFICATE_NOT_FOUND = "No ACTIVE certificate found for Entity";
    public static final String CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY = "CSR must contain either subject or subjectAltName";
    public static final String ENTITY_SUBJECT_CANNOT_BE_NULL = "Entity subject cannot be null";
    public static final String ENTITY_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY = "Entity must contain either subject or subjectAltName";
    public static final String CAENTITY_SUBJECT_CANNOT_BE_NULL_OR_EMPTY = "CAEntity subject cannot be null or empty";
    public static final String KEY_USAGE_MANDATORY_FOR_CA = "KeyUSage is Manadory for CA";
    public static final String MULTIPLE_KEY_GENERATION_ALGORTITHM = "Multiple KeyGeneration Algorithms Provided";
    public static final String INVALID_KEY_GENERATION_ALGORTITHM = "KeyGeneration algorithm specified in CSR not matched with the entity or profiles";
    public static final String CSR_MANDATORY = "Certificate Request is required for entity";
    public static final String ENTITY_NOT_FOUND = "Entity not found";
    public static final String OTP_VALIDATION_FAILED = "Entity OTP and Challenge Password in CSR does not match";
    public static final String OTP_COUNT_REACHED_ZERO = "OTP count reached to zero";
    public static final String ENTITY_OTP_NOT_SET = "Entity does not have OTP but recevied challenge password from CSR";
    public static final String CSR_ENCODING_FAILED = "Could not encode the CSR";
    public static final String CSR_SIGNATURE_INVALID = "CSR singature can not be processed or invalid";
    public static final String CSR_KEY_INVALID = "Error while decoding the public key of CSR";
    public static final String CSR_KEY_ALGORITHM_INVALID = "Algorithm not supported";
    public static final String CSR_GENERATION_FAILED = "CSR Generation Failed";
    public static final String NO_TRUST_PROFILE_FOUND = "No trust profile found for entity";
    public static final String ENTITY_NOT_FOUND_WITH_NAME = "entity not found with Name";
    public static final String ISSUER_CERTIFICATE_ALREADY_EXPIRED = "Invalid Certificate chain. One of the certificates in chain is expired. ";

    public static final String INVALID_CSR = "CSR is not Valid";
    public static final String INVALID_CERTIFICATE_EXTENSIONS = "Provided certificate extensions are not valid";
    public static final String UNSUPPORTED_CERTIFICATE_VERSION = "certificate version is not supported";
    public static final String ISSUER_CA_NOT_FOUND = "Issuer CA not found";
    public static final String KEYPAIR_GENERATION_FAILED = "Keypair Generation Failed";
    public static final String CERTIFICATE_CHAIN_IS_NOT_PROPER = "Given Certificate chain is not proper to store in the key store";
    public static final String KEYSTORE_FILE_NOT_EXIST = "Exception occured while creating keyStore file";
    public static final String DATA_IS_NOT_PROPER = "Data to be stored in key store is not proper.";
    public static final String KEYSTORE_TYPE_IS_NOT_VALID = "Given Keystore type is not valid";
    public static final String ALGORITHM_IS_NOT_FOUND = "Provided algorithm not found ";
    public static final String ECDSA_KEY_SIZE_NOT_SUPPORTED = "Unsupported ECDSA keysize. The given key size is:";
    public static final String ECDSA_KEY_SIZE_WEAK = "Key Generation Algorithm ECDSA with keysizes 160,163 are weak. Use strong Keysizes";
    public static final String FILE_OUTPUT_IS_NOT_CLOSED = "File output stream is not closed";
    public static final String FILE_INPUT_IS_NOT_CLOSED = "File input strean is not closed";
    public static final String CSR_SIGNATURE_GENERATION_FAILED = "Provided algorithm not found ";
    public static final String INVALID_ENTITY_SUBJECT = "Entity Subject should not contain override operator in case of without CSR";
    public static final String INVALID_DN = "DN is not in proper format";
    public static final String INVALID_ENTITY_SAN = "Entity subjectAltName should not contain override operator in case of without CSR";
    public static final String KEY_SIZE_NOT_SUPPORTED = "KeySize is not supported.";
    public static final String ISSUER_NAME_IS_NOT_MATCHED = "Issuer Name in the request is not matched with the Entity Issuer Name.";
    public static final String PKCS10_CERTIFICATE_REQUEST_GENERATION_FAILED = "Failed to generate PKCS10 Certification Request Holder for the CSR to be exported";
    public static final String IO_EXCEPTION = " IO exception Occured while byte conversion or reading input Stream.";

    public static final String EXTERNAL_CA_NOT_FOUND = "External CA not found";
    public static final String EXTERNAL_CA_ISSUER_NOT_FOUND = "CRL Issuer for External CA not found";
    public static final String EXTERNAL_CA_NAME_EMPTY = "External CA name is null or empty";
    public static final String EXTERNAL_CA_NAME_USED_FOR_INTERNAL = "External CA name used for internal CA";
    public static final String CA_ISNT_EXTERNAL_CA = "CA is not external";
    public static final String EXTERNAL_CA_CRL_NOT_FOUND = "External CA hasn't CRLs";
    public static final String EXTERNAL_CA_CRL_EXIST = "External CA has CRLs";
    public static final String EXTERNAL_CA_CRL_INFO_EMPTY = "External CA CRL Info is empty";
    public static final String EXTERNAL_CA_CRL_EMPTY = "External CA CRL is empty";
    public static final String EXTERNAL_CA_IS_USED = "External CA is used in any Trust Profile";
    public static final String CERTIFICATE_ALREADY_IMPORTED = "Certificate already imported";
    public static final String CERTIFICATE_EMPTY = "Certificate is empty";
    public static final String EXTERNAL_CA_NAME_USED_FOR_OTHER_EXTERNAL_CA = "External CA name used for other External CA";
    public static final String CERTIFICATE_WITH_DIFFERENT_SUBJECTDN = "External CA has a certificate with a different subjectDN";
    public static final String PEM_WITH_MORE_CERTIFICATES = "PEM file contains multiple certificates";

    public static final String KEYSTORE_TYPE_NULL = "Key store type is mandatory";
    public static final String UNSUPPORTED_REISSUE_TYPE = "Unsupported reissue type.Supported types are [CA,CA_WITH_IMMEDIATE_SUB_CAS,CA_WITH_ALL_CHILD_CAS]";
    public static final String ISSUER_NOT_FOUND = "Issuer details not found";
    public static final String CERTIFICATE_DATA_IS_NULL = "Certificate for a particular entity/Caentity is null";

    public static final String CHAIN_NOT_SUPPORTED = "Unsupported Operation, only ACTIVE Certificate chain operation allowed";
    public static final String INVALID_CERTIFICATE_STATUS = "Inavlid Certificate Status";
    public static final String ISSUER_CERITICATE_IS_REVOKED_OR_EXPIRED = "In the chain, issuer certificate is revoked or expired";
    public static final String CERTIFICATE_DATA_NULL = "Certificate for a particular entity/Caentity is null";

    public static final String LIMIT_AND_OFFSET_MANDATORY = "Limit and Offset are mandatory";
    public static final String INVALID_LIMIT_AND_OFFSET = "Limit and Offset should not be 0";

    public static final String CERTIFICATE_ID_MANDATORY = "Certificate Id is manadatory to get certificates";
    public static final String CERTIFICATE_FILE_FORMAT_MANDATORY = "Format is manadatory. Supported values are [JKS,P12,PEM,DER].";
    public static final String INCOMPATIBLE_SIGNATURE_KEYGEN_ALGORITHMS = "Failure in generating CSR signature. Found incompatible signature and keygeneration algorithms during generation of certificate!";

    // Error messages for CA Entities
    public static final String ERROR_GETTING_SUBCAS = "Error occured while getting the Sub CAs of a CA Entity ";
    public static final String INVALID_CRL_GENERATION_INFO_FOR_CA = "Invalid CRLGenerationInfo for the CA Entity ";
    // Error Messages renew operation of CA and all CAs in its hierarchy.
    public static final String UNABLE_TO_GET_CA_HIERARCHY = "Error occurred getting hierarchy of the given CA ";

    // Error Messages for Secure communication
    public static final String PKI_CREDM_CERT_REQUEST_XML_FILE_NOT_FOUND = "pkicredentialscertificaterequest xml file not found ";
    public static final String XML_PARSING_ERROR = "Failed to parse the xml ";
    public static final String FAILED_TO_CONSTRUCT_URL = "Failed to construct URL ";
    public static final String FAILED_TO_READ_HOST_NAME = "Failed to read server's host name";
    public static final String INVALID_XML_PKI_CREDM_CERT_REQUEST = "Schema validation failed and hence the XML 'pkimanagercredentialsrequest.xml' is invalid. ";

    // Error Messages for SCEP evnet notification.
    public static final String FAIL_TO_SIGN_SCEP_RESPONSE_MESSAGE = "Fail to sign SCEP response message";
    public static final String UNABLE_TO_CREATE_ENTITY = "Unable to create entity to generate pki-manager credentials ";

    // Error Messages - Certificate Management RBAC
    public static final String SECURITY_VIOLATION_EXCEPTION = "User does not have privilege to perform this operation";

    // Error code for Force validations of Import certificate ( as a part of ExternalRootCA )
    public static final String SUBJECT_ALT_NAME_NOT_FOUND_IN_CSR = "Error Occured while importing Certificate,Subject Alternate name not found in Certificate Request";
    public static final String SUBJECT_ALT_NAME_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,Subject Alternate name not found in imported Certificate";
    public static final String SUBJECT_ALT_NAME_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_SUBJECT_ALT_NAME = "Error Occured while importing Certificate,Subject Alternate Name of certificate does not match with Subject Alternate Name of corresponding CSR.";
    public static final String KEY_USAGE_NOT_FOUND_IN_CSR = "Error Occured while importing Certificate,Key Usage not found in Certificate Request";
    public static final String KEY_USAGE_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,Key Usage not found in imported Certificate";
    public static final String KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_KEY_USAGE = "Error Occured while importing Certificate,Key Usage of certificate does not match with Key Usage of corresponding CSR.";
    public static final String EXTENDED_KEY_USAGE_NOT_FOUND_IN_CSR = "Error Occured while importing Certificate,Extended Key Usage not found in Certificate Request";
    public static final String EXTENDED_KEY_USAGE_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,Extended Key Usage not found in imported Certificate";
    public static final String EXTENDED_KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_EXTENDED_KEY_USAGE = "Error Occured while importing Certificate,Extended Key Usage of certificate does not match with Extended Key Usage of corresponding CSR.";
    public static final String EXTENDED_KEY_USAGE_IS_NULL_INVALID = "Error Occured while importing Certificate,Extended Key Usage is either null or invalid in imported Certificate";
    public static final String BASIC_CONSTRAINTS_NOT_FOUND_IN_CSR = "Error Occured while importing Certificate,BasicConstraints not found in Certificate Request";
    public static final String BASIC_CONSTRAINTS_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,BasicConstraints not found in imported Certificate";
    public static final String BASIC_CONSTRAINTS_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_BASIC_CONSTRAINTS = "Error Occured while importing Certificate,BasicConstraints of certificate does not match with BasicConstraints of corresponding CSR.";
    public static final String SUBJECT_KEY_IDENTIFIER__NOT_FOUND_IN_CSR = "Error Occured while importing Certificate,Suject Key Identifier not found in Certificate Request";
    public static final String SUBJECT_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,Subject Key Identifier not found in imported Certificate";
    public static final String AUTHORITY_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE = "Error Occured while importing Certificate,Authority Key Identifier not found in imported Certificate";
    public static final String SUBJECT_KEY_IDENTIFIER_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_SUBJECT_KEY_IDENTIFIER = "Error Occured while importing Certificate,SubjectKeyIdentifier of certificate does not match with SubjectKeyIdentifier of corresponding CSR.";
    public static final String EXTENSION_IS_NULL = "Error Occured while importing Certificate,Certificate Extension is Null";
    public static final String CSR_EXTENSION_IS_NULL = "Error Occured while importing Certificate,Extension is Null in the CSR";

    // Error Messages for External Root CA
    public static final String NOT_ROOT_CA = "Given CA is not a Root CA.";
    public static final String INACTIVE_CA = "Invalid CA For the operation. CA should be Active";
    public static final String ROOT_CA_NOT_FOUND = "Root CA not found";

    // Error messages - Rest related methods
    public static final String ERROR_GETTING_ACTIVE_ISSUERS = "Error occured while retrieving issuers that are active from database";

    public static final String NO_VALID_CERTIFICATE_CHAIN_FOR_CA = "No valid Certificate chain for the CA";
    public static final String ERROR_WHILE_IMPORT_CERT = "Exception occurred when importing certificate signed by external CA";
    public static final String CSR_ALREADY_EXISTS = "CSR Already Exists for the given CA";

    // Error Codes for RFCValidation(as a part of ExternalRootCA)
    public static final String BASIC_CONSTRAINTS_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,BasicConstraints Validation failed(isCA =false)";
    public static final String BASIC_CONSTRAINTS_PATH_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,BasicConstraints Path Validation failed(path length is null or less than zero)";
    public static final String BASIC_CONSTRAINTS_NULL = "Error Occured in RFCValidation while importing Certificate,Basic constraints Field Value is null, For a CA certificate Basic constraints is mandatory";
    public static final String CA_IS_NOT_EXTERNAL_CA = "Error Occured in RFCValidation while importing Certificate,CA is not external";
    public static final String COUNTRY_CODE_LENGTH_INVALID = "Error Occured in RFCValidation while importing Certificate,Country Code Length Should be 2 in IssuerDN field";
    public static final String INVALID_COUNTRY_CODE = "Error Occured in RFCValidation while importing Certificate,Country Code is Invalid";
    public static final String KEY_USAGE_TYPE_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,For CA, KeyCertSign,CRLSign,DigitalSignature keyUsagetypes are mandatory";
    public static final String KEY_USAGE_EXTENSION_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate, Critical value should True for KeyUsage Extension";
    public static final String SERIAL_NUMBER_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,Serial number validation failed(length should not be greater than 20 octects as per RFC and Serial number should be non-negative)";
    public static final String INVALID_SUBJECT_ALT_NAME_EXTENSION = "Error Occured While Validating SubjectAltNameValidation";
    public static final String SUBJECT_KEY_IDENTIFIER_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,Subject Key Identifier Validation Failed";
    public static final String CERTIFICATE_EXTENSION_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,Duplicate Extension Found";
    public static final String EXTENSION_NON_CRITICAL = "Error Occured in RFCValidation while importing Certificate,Extension should be non-critical";
    public static final String ACCESS_METHOD_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,Access Description Should contain (id_ad_ocsp or id_ad_caIssuers) Access descriptors ";
    public static final String EXTENSION_VALUE_NULL = "Error Occured in RFCValidation while importing Certificate,Extension value is null";
    public static final String ISSUER_UNIQUE_IDENTIFIER_IS_NOT_ALLOWED = "Error Occured in RFCValidation while importing Certificate,Issuer Unique Identifier Field is allowed only for Certificate of version 2 or 3 ";
    public static final String SUBJECT_UNIQUE_IDENTIFIER_IS_NOT_ALLOWED = "Error Occured in RFCValidation while importing Certificate,Subject Unique Identifier Field is allowed only for Certificate of version 2 or 3 ";
    public static final String EXTENSION_CRITICAL = "Error Occured in RFCValidation while importing Certificate,Extension should be critical";
    public static final String OCTECT_VALUE_NULL = "Error Occured in RFCValidation while importing Certificate,Failed to get Octects from the certificate";
    public static final String AUTHORITY_KEY_IDENTIFIER_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,Authority key Identifier validation Failed";
    public static final String DISTRIBUTION_POINTS_NULL = "Error Occured in RFCValidation while importing Certificate,Distribution Points are null";
    public static final String CRLDISTRIBUTION_POINT_INFO_VALIDATION_FAILED = "Error Occured in RFCValidation while importing Certificate,DistributionPoint must consist either distributionPoint or cRLIssuer Fields";
    public static final String URI_IS_NULL = "Error Occured in RFCValidation while importing Certificate,URI is null in CRLDistributionPointInfo";
    public static final String FAILED_TO_DOWNLOAD_CRL = "Error Occured While downloading CRL from CRLDistributionPointURI";
    public static final String ALGORITHM_NOT_FOUND_IN_DB = "Error Occured in RFCValidation while importing Certificate,No algorithms found in database for the given AlgorithmType";
    public static final String CERTIFICATE_ALREADY_PRESENT = "Error Occured in RFCValidation while importing Certificate,Active Certificate already exists in the database with same serial number";
    public static final String CRL_URI_IS_INVALID = "Error Occured in RFCValidation while importing Certificate,CRL URI in CRLDistributionPointInfo must start with http:// or ldap://";
    public static final String INVALID_PUBLIC_KEY = "Error Occured in RFCValidation while importing Certificate,Invalid public key.";
    public static final String CERTIFICATE_FACTORY_NOT_FOUND = "Error Occured in RFCValidation while importing Certificate,Failed to get CertificateFactory instance";
    public static final String FAIL_TO_GENERATE_CRL = "Error Occured in RFCValidation while importing Certificate,Failed to read CRL";
    public static final String UNSUPPORTED_ENCODING_EXCEPTION = "Error Occured in RFCValidation while importing Certificate,Unsupported Encoding Exception";
    public static final String INVALID_SIGNATURE = "Error Occured in RFCValidation while importing Certificate,Signature applied is invalid";
    public static final String DB_EXCEPTION = "Error Occured in RFCValidation while importing Certificate,DB Error while performing CRUD operations";
    public static final String ISSUER_IS_NULL_OR_EMPTY = "Error Occured in RFCValidation while importing Certificate,Issuer Name is null or empty in the certificate provided";

    // Error code for Basic validations of Import certificate ( as a part of ExternalRootCA )
    public static final String CSR_NOT_FOUND = "Error Occured in BasicValidation while importing Certificate,CSR not found for the given CA to import its certificate ";
    public static final String PUBLIC_KEY_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_PUBLIC_KEY = "Error Occured in BasicValidation while importing Certificate,Public key in the certificate does not match with public key of corresponding CSR. ";
    public static final String SUBJECT_DN_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_SUBJECT_DN = "Error Occured in BasicValidation while importing Certificate,Subject DN of certificate does not match with subject DN corresponding CSR. ";
    public static final String AUTHORITY_KEY_VALIDATION_FAILED = "Error Occured in BasicValidation while importing Certificate,Authority Key identifier of imported certificate does not match with Issuer certificate subject key identifier";
    public static final String ISSUER_CERT_NOT_FOUND = "Error Occured in BasicValidation while importing Certificate,Unable to find issuer certificate for the imported certificate ";

    // Error code for chain validations of Import certificate ( as a part of ExternalRootCA ) which is signed by external CA.
    public static final String CERTIFICATE_ENCODING_FAILED_WHILE_CHAIN_VALIDATION = "Exception occured while encoding the certificate during external certificate chain validation";
    public static final String EXTERNAL_CA_CERTIFICATE_NOT_FOUND = "Error Occured while importing Certificate,External CA Certificates not found";
    public static final String ISSUER_CERTIFICATE_NOT_FOUND = "Error Occured while importing Certificate,External CA Certificates not found";
    public static final String INVALID_ISSUER_NAME = "Error Occured while importing Certificate,Invalid Issuer name in import certificate";
    public static final String ISSUER_CERTIFICATE_ALREADY_REVOKED_OR_EXPIRED = "Error Occured while importing Certificate,Invalid Certificate chain. Issuer certificate in chain is already revoked or expired.";
    public static final String CERTIFICATE_PARSING_FAILED = "Exception occured while parsing the x509certificate to certificate";

    public static final String OCCURED_IN_CREATING_CUSTOM_CONFIGURATION = " Occured in creating Custom Configuration";
    public static final String OCCURED_IN_UPDATING_CUSTOM_CONFIGURATION = " Occured in updating Custom Configuration";
    public static final String OCCURED_IN_CUSTOM_CONFIGURATION_ALREADY_EXISTS = "Custom Configuration Already Exists";
    public static final String OCCURED_IN_CUSTOM_CONFIGURATION_NOT_FOUND = "Custom Configuration Not Found";
    public static final String OCCURED_IN_DELETING_CUSTOM_CONFIGURATION = " Occured in deleting Custom Configuration";
    public static final String ISSUER_NULL_IN_CERTIFICATE = "Error Occured while publishing Certificate to TDPS Service,Issuer not set in the certificate";

    public static final String DUPLICATE_NOTIFICATION_SEVERITY = "Duplicate Notification Severity";
    public static final String NOTIFICATION_SEVERITY_IS_MISSING = "Mandatory field Notification Severity is Missing";
    public static final String PERIOD_BEFORE_EXPIRY_IS_MISSING = "Mandatory field Period Before Expiry is Missing";
    public static final String FREQUENCY_OF_NOTIFICATION_IS_MISSING = "Mandatory field Frequency of Notification is Missing";
    public static final String INVALID_FREQUENCY_OF_NOTIFICATION_FOR_CRITICAL = "Frequency of Notification should be 1 in case of CRITICAL Severity";
    public static final String INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MAJOR = "Frequency of Notification should be 1 or 2 in case of MAJOR Severity";
    public static final String INVALID_FREQUENCY_OF_NOTIFICATION_FOR_WARNING = "Frequency of Notification should be between 1 and 4 in case of WARNING Severity";
    public static final String INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MINOR = "Frequency of Notification should be between 1 and 7 in case of MINOR Severity";
    public static final String INVALID_PERIOD_BEFORE_EXPIRY_FOR_CRITICAL = "PeriodBeforeExpiry should be between 1 and 30 in case of CRITICAL Severity";
    public static final String INVALID_PERIOD_BEFORE_EXPIRY_FOR_MAJOR = "PeriodBeforeExpiry should be between 31 and 60 in case of MAJOR Severity";
    public static final String INVALID_PERIOD_BEFORE_EXPIRY_FOR_WARNING = "PeriodBeforeExpiry should be between 61 and 90 in case of WARNING Severity";
    public static final String INVALID_PERIOD_BEFORE_EXPIRY_FOR_MINOR = "PeriodBeforeExpiry should be betweeen 91 and 180 in case of MINOR Severity";
    public static final String INVALID_NOTIFICATION_SEVERITY = "Invalid Notification Severity";

    public static final String NO_ENTITY_FOUND = "No Entity found with given name. Please refer an existing entity and try again.";
    public static final String INVALID_KEY_REQUEST_FOR_INACTIVE_CA = "Given entity is in inactive status, Please provide newKey value as true";

    // Error codes for 5G
    public static final String OTP_EXPIRED = "OTP has expired for the given entity";
    public static final String OTP_NOT_SET = "OTP is not set for the given entity";
    public static final String OTP_VALIDITY_PERIOD_NOT_IN_RANGE = "OTP Validity Period value is not with in the Expected Range ";

    public static final String EXTERNAL_CA_IS_USED_AS_ISSUER = "External CA %s cannot be deleted as it issued certificates for other Entities.";

    //Error code for SUID
    public static final String UNACCEPTED_SUID_ENTITY_VALUE_ERROR = "The SUID provided in the certificate profile is false. So, SUID value cannot be accepted in entity";
    public static final String INVALID_SUID_ENTITY_VALUE_ERROR = "The SUID provided in the entity profile contains override operator. So, SUID value in entity is mandatory";
    public static final String UNACCEPTED_SUID_ENTITY_PROFILE_VALUE_ERROR = "The SUID provided in the certificate profile is false. So, SUID value cannot be accepted in entityprofile";
    public static final String UNSUPPORTED_SUID_CHARACTERS_ERROR = "Subject unique identifier field contains unsupported characters ?\\=,/\"";
    public static final String UNSUPPORTED_SUID_EP_CHARACTERS_ERROR = "Subject unique identifier field contains unsupported characters \\=,/\"";
}
