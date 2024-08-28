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
package com.ericsson.oss.itpf.security.pki.core.common.constants;

/**
 * Class that defined all error messages from the validations performed.
 * 
 */
public class ErrorMessages {
    // TODO: Check and move applicable error messages to pki-common. User story ref : TORF-54827
    // Error Messages
    public static final String NO_SUCH_AlGORITHM = "Algorithm provided is not valid ";
    public static final String CERTIFICATE_ENCODING_EXCEPTION = "Invalid encoding of certificate";
    public static final String SIGNATURE_GENERATION_FAILED = "Exception while generating certificate signature ";
    public static final String UNSUPPORTED_CERTIFICATE_VERSION = "Unsupported Certificate version ";
    public static final String CSR_SIGNATURE_GENERATION_FAILED_FOR_CA = "CSR signature generation failed for CA. ";
    public static final String INVALID_KEY = "Key size is not valid or invlaid encoding of key ";
    public static final String INVALID_SANFIELD_TYPE = "Invalid SubjectAltNameFieldType ";
    public static final String INVALID_KEYUSAGE_TYPE = "Invalid KeyUsageType ";
    public static final String IO_EXCEPTION = "issue with provided input ";
    public static final String CERTIFICATE_EXCEPTION = "Error parsing certificate to get the extension ";
    public static final String INVALID_REASON_CODE = "Invalid Reason code passed for CRLs ";
    public static final String CERTIFICATE_AUTHORITY_NOT_FOUND = "CA does not exist in PKI Core ";
    public static final String ALGORITHM_NOT_FOUND_IN_DATABASE = "Given algorithm not found in PKI core database. ";
    public static final String ECDSA_KEY_SIZE_NOT_SUPPORTED = "Key Generation Algorithm ECDSA with keysize 512 is not supported";
    public static final String ECDSA_KEY_SIZE_WEAK = "Key Generation Algorithm ECDSA with keysizes 160,163 are weak. Use strong Keysizes";
    public static final String INVALID_CSR_ENCODING = "CSR encoding is not valid or not in correct format. ";
    public static final String INVALID_KEY_IN_CSR = "Keys provided in the CSR are not valid. ";
    public static final String INVALID_OBJECT_FOR_SERIALIZATION = "Provided object for serialization is not valid. ";
    public static final String INVALID_OBJECT_FOR_DESERIALIZATION = "Provided object for deserialization is not valid. ";
    public static final String CLASS_NOT_FOUND_FOR_DESERIALIZATION = "Class that to be deserialized not found. ";
    public static final String ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID = "Algorithm to build keyidentifier is not valid. ";
    public static final String EXTENSION_ENCODING_IS_INVALID = "Extension encoding not proper. ";
    public static final String ENTITY_ALREADY_EXISTS_IN_DATABASE = "Entity exists in database. ";
    public static final String ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE = "Error occured in retreiving from database. ";
    public static final String INVALID_CERTIFICATE_EXTENSION = "Invalid Certificate Extension ";
    public static final String ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION = "Error occurred while building extended key usage extension ";
    public static final String CRMF_EXCEPTION = "Error while extracting Public Key from CRMF Request Message";
    public static final String ERROR_GENERATING_SERIAL_NUMBER = "Serial number generation failed ";
    public static final String ERROR_GENERATING_KEY_PAIR = "Unable to generate key pair ";
    public static final String DATA_OUT_OF_SYNC = "PKI Core Data out of Sync with PKI Manager Data";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate does not exists";
    public static final String CERTIFICATE_EXPIRED = "Certificate is Expired";
    public static final String CERTIFICATE_REVOKED = "Certificate is Revoked";
    public static final String CERTIFICATE_GENERATION_INFO_ALREADY_EXISTS = "Certificate generation info already exists in the system";
    public static final String CERTIFICATE_GENERATION_INFO_NOT_FOUND = "Certificate generation info not found in the system";
    public static final String CSR_STATUS_UPDATION_FAILED = "Error occurred while updating the CSR";
    public static final String INVALID_CERTTIFICATE_EXCEPTION = "Certificate for given CA entity is invalid";

    public static final String CRL_NOT_FOUND = "CRL does not exists";
    public static final String CRL_GENERATION_INFO_NOT_FOUND = "CRL generation info does not exists";
    public static final String INTERNAL_ERROR = "An error occured while processing the request";
    public static final String CONFIGURATION_PROPERTY_NOT_FOUND = "Configuration Property Not found";
    public static final String CONFIGURATION_PROPERTY_VALUE_NULL = "Configuration Property Value is null";
    public static final String ERROR_OCCURED_IN_UPDATING_DATABASE = "Error occured in updating the database entity";
    public static final String ERROR_OCCURED_IN_STORING_DATABASE = "Error occured in storing the database entity";
    public static final String CRL_GENERATION_EXCEPTION = "Error while generating CRL";
    public static final String INVALID_ISSUEING_DISTRIBUTION_POINT = "Issuing Distribution Point is not valid";
    public static final String UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER = "Active Key Pair does not exist for CA ";
    public static final String UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS = "Unable to generate CSR for the CA ";
    public static final String INVALID_CERTIFICATE_EXTENSIONS = "Provided certificate extensions are not valid";
    public static final String INVALID_CRL_EXTENSIONS = "Error while adding CRL Extensions";
    public static final String UNABLE_TO_UPDATE_WITH_KEYIDENTIFIERDATA = "Unable to upadate KeyIdentifierData for CA";
    public static final String AUTOMATIC_CRL_GENERATION_JOB_FAILED = "Automatic CRL generation job failed ";
    public static final String FAILED_TO_RECREATE_TIMER = "Failed to recreate timer for the changed configuration parameter ";
    public static final String EXTENSIONS_BUILDING_FAILED = "Error occurred when generating CSR with extensions provided. ";

    public static final String CA_IS_NOT_ROOT_CA = "Given CA is not a Root CA ";
    public static final String CA_NEW_OR_ACTIVE = "CA Status should be NEW or ACTIVE ";
    public static final String ERROR_WHILE_IMPORT_CERT = "Exception occurred when importing certificate signed by external CA";
    public static final String UNABLE_TO_FIND_CSR_FOR_CERT = "CSR for the imported certificate not found in the database. ";

}
