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

package com.ericsson.itpf.security.pki.cmdhandler.api.exception;

/**
 * Class to Encapsulate all PKI Error Codes and their Suggested Solutions
 *
 * @author xsumnan on 29/03/2015.
 */

public class PkiErrorCodes {

    public static final String CHECK_ONLINE_HELP = "Please check Online Help for correct syntax.";
    public static final String CONSULT_ERROR_LOGS = "An error occurred while executing the PKI command on the system. Consult the error and logs for more information.";
    public static final String SYNTAX_ERROR = "Command syntax error";
    public static final String UNEXPECTED_INTERNAL_ERROR = "Unexpected Internal Error, please check the error log for more details.";
    public static final String PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT = "Invalid xml format found, Please see online help for correct xml format";
    public static final String UNSUPPORTED_COMMAND_ARGUMENT = "Unsupported PKI command argument";
    public static final String UNEXPECTED_SYSTEM_ERROR = "This is an unexpected system error, please check the error log for more details.";
    public static final String CA_NOT_FOUND_EXCEPTION = "CA not found, Try with existing CA";

    public static final String INVALID_CA_ENTITY = "The CA entity with name  %s is not found.";
    public static final String PROFILE_ALREADY_EXIST_EXCEPTION = "Invalid Argument Profile already exists, Try with diferent name";
    public static final String PROFILE_NOT_FOUND = "No profile(s) found, try with valid Profile";
    public static final String NO_PROFILE_OF_GIVEN_TYPE = "No profile found with matching criteria";
    public static final String PROFILE_IN_USE = "Profile in use";
    public static final String ENTITY_ALREADY_EXISTS = "Invalid Argument Entity already exists";
    public static final String ENTITY_NOT_FOUND = "Entity not Found, try with valid Entity";
    public static final String INVALID_ENTITY = "Parameters in the entity are invalid.";
    public static final String NO_ENTITY_OF_GIVEN_TYPE = "No entity found with matching criteria";

    public static final String UNABLE_GENERATE_CERTIFICATE = "Unable to generate the Certificate.";
    public static final String ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY = "Entity Name cannot be null or empty.";
    public static final String CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY = "Category Name cannot be null or empty.";
    public static final String CATEGORY_IS_NOT_APPLICABLE = "Category is not applicable for CAEntity";
    public static final String CSR_FORMAT_ERROR = "Generation of certificate failed: Input CSR file format error.";
    public static final String NO_ENTITY_FOUND = "No Entity found with given name. Please refer an existing entity and try again.";
    public static final String NO_TRUST_ENTITY_FOUND = "No Trust certificate found with given input data. Please refer an existing entity and try again.";
    public static final String INVALID_CSR_FILE = "Input CSR file format error. Generation of Entity certificate(s) failed.";
    public static final String ENTITY_DOES_NOT_EXIST = "Invalid argument value: Entity doesn't exist";
    public static final String CERTIFICATE_STATUS_NOT_SUPPORTED = "Certificate status not supported. Supported values are [active,inactive,revoked,expired] ";
    public static final String UNSUPPORTED_REISSUE_TYPE = "Unsupported reissue type. Supported values are [renew,rekey]";
    public static final String FORMAT_NOT_SUPPORTED = "Format is not supported. Supported values are [JKS,P12,PEM,DER].";
    public static final String INVALID_PASSWORD = "Password field cannot be null or empty";
    public static final String EXCEPTION_IN_CERTIFICATE_GENERATION = "Exception during Certificate generation";
    public static final String EXCEPTION_IN_CERTIFICATE_PARSER = "Exception during Certificate parsing";
    public static final String EXCEPTION_IN_KEYPAIR_GENERATION = "Exception during key pair generation";
    public static final String CERTIFICATE_ALREADY_EXISTS = "Certificate Already Exists";
    public static final String CSR_GENERATION_EXCEPTION = "Exception While generating CSR";
    public static final String NO_CERTIFICATE_FOUND = "Certificate not found for the entity";
    public static final String UNABLE_LIST_CERTIFICATE = "Unable to List Certificates";
    public static final String ENTITY_CERTIFICATE_NOT_FOUND = "No active Entity certificate(s) found for the entity.";
    public static final String CA_ENTITY_CERTIFICATE_NOT_FOUND = "Issuer CA certificate(s) not found for the entity.";
    public static final String NO_VALID_CA_ENTITY_CERTIFICATE_FOUND = "No valid CA certificate(s) found .";
    public static final String EXCEPTION_STORING_CERTIFICATE = "Exception while storing the certificate";
    public static final String INVALID_CERTIFICATE_REQUEST = "Certificate Request is invalid, please check the request";

    public static final String ALGORITHM_NOT_FOUND_EXCEPTION = "Provided Algorithm not found, Please check online help for the list of supported algorithms.";
    public static final String ALGORITHM_NOT_FOUND_WITH_STATUS = "Algorithm not found with the given status";
    public static final String INVALID_ARGUMENT = "Invalid argument value: ";
    public static final String MISSING_MANDATORY_FIELD = "Missing mandatory field: ";
    public static final String EXTCACERTIFICATE_ALREADY_EXIST = INVALID_ARGUMENT + CERTIFICATE_ALREADY_EXISTS;
    public static final String EXTCANAME_IS_INTERNAL = "CA is not external";
    public static final String EXTCANAME_IS_WRONG = "CA name already used for different subject";
    public static final String EXTCA_NOT_FOUND = "External CA not found with given name";
    public static final String NETWORK_PROBLEM_FOR_EXTERNAL_CRL = "Network problem: cannot download CRL file";

    public static final String SUGGEST_SOLUTION = "Suggested Solution : ";
    public static final String SUGGEST_CHECK_EXTCANAME = SUGGEST_SOLUTION + "Please check the specified External CA name.";
    public static final String SUGGEST_CHECK_EXTCANAME_EMPTY = SUGGEST_SOLUTION + "The External CA name is empty.";
    public static final String SUGGEST_CHECK_EXTCANAME_OR_CERT_EMPTY = SUGGEST_SOLUTION + "Please check the specified External CA name or certficate.";
    public static final String SUGGEST_CHECK_EXTCA_CERTIFICATE = "Suggested Solution : Use a valid External CA certificate.";
    public static final String SUGGEST_CHECK_CANAME_FOR_IMPORT_EXTCA = SUGGEST_SOLUTION + "The CA name is already existing but it is an internal CA.";
    public static final String SUGGEST_CHECK_TRUST_PROFILE_FOR_EXTERNAL = SUGGEST_SOLUTION + "Please check and update any profiles including the specified external CA";
    public static final String SUGGEST_CHECK_CERTIFICATE_SN = SUGGEST_SOLUTION + "Please check the specified serial number.";
    public static final String SUGGEST_CHECK_CERTIFICATE = SUGGEST_SOLUTION + "Please Use valid Certificate.";
    public static final String SUGGEST_CHECK_MISMATCH_CERT_CA = SUGGEST_SOLUTION
            + "Please use the \"--name\" option with a different CA name. When the option is not specified (as in the example) the Subject Common Name is used by default.";
    public static final String SUGGEST_CHECK_CERTIFICATE_ALREADY_PRESENT = SUGGEST_SOLUTION
            + "The certificate is already existing in the system, please remove the related external CA before importing it again.";
    public static final String SUGGEST_CHECK_CANAME_FOR_UPDATECRL = SUGGEST_SOLUTION
            + "Please check the specified CA name. Note that before adding a CRL file to the system the related external CA should have been imported.";
    public static final String SUGGEST_CHECK_URL = SUGGEST_SOLUTION + "Please verify that the CRL URL is accessible from the ENM installation and that no firewall is blocking the HTTP/HTTPS ports.";
    public static final String SUGGEST_CHECK_EXTCA_ISSUERNAME = SUGGEST_SOLUTION + "Please check the specified issuer name for External CA CRL.";
    public static final String WARNING_CHECK_EXTCA_CERTIFICATE = "WARNING : The given certifcate is going to expire.";


    public static final String IO_ERROR = "IO exception Occured while byte conversion or writing to Output Stream.";
    public static final String KEYSTORE_PROCESSING_EXCEPTON = "Exception occured while processing key store";

    public static final String ROOT_CA_CANNOT_REVOKED_CERTIFICATE = "Root CA cannot be revoked.";
    public static final String CERTIFICATE_ALREADY_REVOKED_EXCEPTION = "Certificate already revoked.";
    public static final String REVOCATION_REASON_NOT_SUPPORTED = "Revocation Reason not supported, please check user guide or online help for the list of supported revocation reasons.";
    public static final String ISSUER_NAME_CANNOT_BE_NULL_OR_EMPTY = "Issuer Name cannot be null or empty.";
    public static final String CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY = "Certificate Serial Number cannot be null or empty.";
    public static final String SUBJECT_DN_CANNOT_BE_NULL_OR_EMPTY = "Subject DN cannot be null or empty.";
    public static final String ISSUER_DN_CANNOT_BE_NULL_OR_EMPTY = "Issuer DN cannot be null or empty.";
    public static final String EXPIRED_CERTIFICATE = "The given certificate is expired.";
    public static final String CERTIFICATE_EXPIRED_EXCEPTION = "Use valid Certificate for operation";
    public static final String ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA = "Issuer Certificate for the Entity is already revoked, Issuer Certificate must be valid to revoke Entity Certificate.";
    public static final String ISSUER_NOT_FOUND_EXCEPTION = "Issuer is not found, Please refer to an existing issuer.";
    public static final String INVALID_DATE_FORMAT = "Invalid argument: Date format error.Supported Format is yyyy-MM-dd HH:mm:ss.";
    public static final String INVALID_ENTITY_FOR_REVOCATION = "Certificate revocation failed.Entity name may be incorrect. Please check the logs for more information.";
    public static final String CERTIFICATE_NOT_FOUND_WITH_CERTIFICATE_IDENTIFIER = "Certificate revocation failed.The issuer name or Certificate Serial Number is incorrect. Please check the logs for more information.";
    public static final String CERTIFICATE_NOT_FOUND_WITH_DNBASED_IDENTIFIER = "Certificate revocation failed.The subject DN or issuer DN or serial Number may be incorrect. Please check the logs for more information.";
    public static final String ISSUER_CERTIFICATE_NOT_FOUND_FOR_GIVEN_EXTERNAL_CA = "Error occured while importing certificate, issuer certificate not found for given external sub CA. ";

    public static final String EXCEPTION_IN_CRL_GENERATION = "Exception occured during CRL generation. ";
    public static final String EXCEPTION_STORING_CRL = "Exception while storing the CRL.";
    public static final String CRL_NUMBER_CANNOT_BE_NULL_OR_EMPTY = "CRL Number can not be null or empty.";

    public static final String CRL_DOWNLOAD_FAILED = "CRL download failed ";
    public static final String CERTIFICATE_STATUS_NO_CANNOT_BE_NULL_OR_EMPTY = "Certificate Status cannot be null or empty.";
    public static final String INVALID_SERIAL_NUMBER = "Certificate not found with the given Serial Number. Please check the logs for more information.";
    public static final String INVALID_CA_AND_SERIAL_NUMBER = "Certificate not found with the given CA name and Serial Number. Please check the logs for more information.";
    public static final String INVALID_CERTIFICATE_STATUS_FOR_CRL_DOWNLOAD = "The CRL can not be downloaded for the CA Certificate Status ";

    public static final String CRL_NOT_FOUND_FOR_LISTING_CRL = "CRL is not yet generated for CA Entity ";
    public static final String CRL_NOT_FOUND_FOR_DOWNLOAD_CRL = "No existing CRL found for CA entity";

    public static final String CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT = "Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax.";
    public static final String MULTIPLE_CERTIFICATE_STATUS_NOT_ALLOWED = "Multiple CA certificate statuses are not allowed.Please check user guide or online help for command syntax.";
    public static final String CRL_GENERATION_FAILED = "CRL generation failed.";
    public static final String CRL_GENERATION_FAILED_INVALID_CERTIFICATE_STATUS = CRL_GENERATION_FAILED + "The CRL can not be generated for the CA Certificate Status %s "
            + CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT;

    public static final String INVALID_CERTIFICATE_STATUS_FOR_LIST_CRL = "CRL listing failed.The CRL can not be listed for the CA Certificate Status %s "
            + CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT;
    public static final String INVALID_CERTIFICATE_STATUS_FOR_DOWNLOAD_CRL = "CRL download failed.The CRL can not be downloaded for the CA Certificate Status %s "
            + CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT;
    public static final String CERTIFICATE_STATUS_CANNOT_BE_NULL_OR_EMPTY = "Certificate Status cannot be null or empty.";

    public static final String CERTIFICATE_LISTING_FAILED = "Certificate list operation failed. The CA entity name or CA Certificate Serial Number is incorrect. Please check the logs for more information.";

    public static final String NO_ENTITY_IS_ISSUED_BY_GIVEN_CA_AND_SERIAL_NUMBER = "No Entity is issued with the given CA and serial Number as inputs.";

    public static final String INVALID_CERTIFICATE_STATUS = "The CRL can not be downloaded for the CA Certificate Status ";

    public static final String HOST_NOT_FOUND = "Host configured is null ";

    public static final String EXCEPTION_IN_CERTIFICATE = "Certificate file contains more than one certificate";

    public static final String CERTIFICATE_WITH_STATUS_NOT_FOUND = "Certificate not found with the given Certificate Status. Please check the logs for more information.";

    public static final String INVALID_ROOT_CA_ENTITY = "Given Entity name is not Root CA.";

    public static final String ROOT_CA_NOT_FOUND_EXCEPTION = "Given CA entity name is not found.";

    public static final String INACTIVE_CA_ENTITY = "Given Entity name is not active.";

    public static final String INVALID_CERTIFICATE = "Import certificate failed. Certificate is invalid.";
    public static final String INVALID_CSR_EXCEPTION = "Import certificate failed. Certificate is not matching with latest requested CSR.";

    public static final String SUGGEST_CHIAN_REQUIRED = SUGGEST_SOLUTION + "Supported values for chainrequired parameter are true or false";
    public static final String UNSUPPORTED_CHAIN_REQUIRED = "Unsupported value for chainrequired attribute.";

    public static final String UNSUPPORTED_CERTIFICATE_STATUS = "Certificate status not supported. Supported values are [active,inactive] ";
    public static final String SECURITY_VIOLATION_EXCEPTION = "User does not have privilege to perform this operation";

    public static final String RETRY = " retry ";
    public static final String SERVICE_ERROR = " Internal service error occurred ";
    public static final String RUNTIME_EXCEPTION = " Exception occured during run time ";
    public static final String INVALID_INVALIDITY_DATE = " Invalid invalidity date ";

    public static final String CERTIFICATE_REVOKED_EXCEPTION = "CA Certificate is revoked.";
    public static final String CRL_GENERATION_INFO_NOT_FOUND = "CRLGenerationInfo is not found.";

    public static final String CERTIFICATE_WITH_DIFFERENT_SUBJECTDN = "External CA has a certificate with a different subjectDN";

    private PkiErrorCodes() {
    }
}
