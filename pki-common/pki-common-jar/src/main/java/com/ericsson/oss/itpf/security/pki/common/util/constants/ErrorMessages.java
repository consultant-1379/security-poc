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
package com.ericsson.oss.itpf.security.pki.common.util.constants;

/**
 * 
 * This class contains all the error messages which will be used as the exception descriptions of common utility classes.
 * 
 * @author tcssher
 * 
 */
public class ErrorMessages {

    public static final String AUTH_FAILED = "Authorization failed.";
    public static final String CMP_PROCESS_ERROR = "Unexcpected error while processing CMP message.";
    public static final String INVALID_CA_NAME = "Invalid CA name.";
    public static final String INVALID_CERTIFICATE = "Invalid certificate.";
    public static final String INVALID_PUBLIC_KEY = "Invalid public key.";
    public static final String INVALID_PRIVATE_KEY = "Invalid private key.";
    public static final String INVALID_MESSAGE = "Not valid CMPv2 message.";
    public static final String INVALID_RESPONSE = "Not valid CMPv2 response message.";
    public static final String INVALID_USER = "Invalid user name.";
    public static final String NOT_SUPPORTED_REQUEST_TYPE = "Not supported request type.";
    public static final String UNEXPECTED_ERROR = "Unexpected exception/error.";
    public static final String UNKNOWN_MESSAGE_TYPE = "Unknown message type.";
    public static final String SENDER_RECIPIENT_DIFFERS = "The recipient CA is not tha same as the issuer of the signer certificate.";
    public static final String NO_SUCH_PROVIDER = " Bouncy Castle provider may not be present.";
    public static final String ALGORITHM_OID_NOT_PRESENT_IN_CACHE = "Algorithm Cache is not initialized properly as there are not algorithm IDs present.";
    public static final String INVALID_ALGORITHM = " Algorithm is not supported.";
    public static final String INVALID_KEYSTORE = " KeyStore is invalid and hence can not be used.";
    public static final String INVALID_SIGNATURE = "Signature applied is invalid";
    public static final String INVALID_PARAMETER = "Invalid parameter while building CertificatePath";
    public static final String INVALID_CONFIGURATION_DATA_PRESENT = "Configuration data was not initialized properly";
    public static final String ISSUER_IS_NULL_IN_CERTIFICATE = "Issuer Name is null in the certificate provided";
    public static final String IO_STREAM_COULD_NOT_BE_CLOSED = "IO stream could not be closed properly";
    public static final String CERTIFICATE_EXCEPTION = "Certificate Exception";
    public static final String CERT_CONF_FORMAT_ERROR = "Certificate Confirmation is in invalid Format";
    public static final String CMP_IN_PROGRESS = "CMP service is still in progress";
    public static final String DIGITAL_SIGNATURE_ERROR = "Digital Signature Validation Failed";
    public static final String BODY_MESSAGE_TYPE_ERROR = "Invalid incoming PKI message type";
    public static final String HEADER_SENDER_FORMAT_ERROR = "RequestMessage header sender/recipient format error";
    public static final String HEADER_TRANSACTION_ID_IN_USE = "Enrollment Transaction ID is already in use";
    public static final String TRANSACTIONID_RECVD_NULL = "Transaction ID is empty";
    public static final String INVALID_DN = "DN is not in proper format";

    public static final String FILE_NOT_FOUND_IN_PATH = "File is not found in the specified location";
    public static final String UNEXPECTED_FILE_EXTENSION = "Invalid File Extension ";

    public static final String NONCE_MISMATCH = "Mismatch in Nonce";
    public static final String NONCE_RECIVED_ARE_NULL = "Nonce recived are null";
    public static final String SESSION_NOT_FOUND_IN_DB = "Transaction corresponding the current message was not found in the database.";
    public static final String CERTIFICATE_IS_NULL = "User certificate Or SignerCert is NULL";
    public static final String INVALID_CERTIFICATE_VERSION = "Certificate version is invalid";
    public static final String CERTIFICATE_FACTORY_NOT_FOUND = "Failed to get CertificateFactory instance";
    public static final String CERTIFICATE_PATH_BUILDER_ERROR = "Error while building certificate path due to invalid parameters.";
    public static final String FAILED_TO_CONVERT_STRING_TO_DURATION = "Failed to convert String to Duration";

    // JKS/InitialConfiguration exceptions:
    public static final String JKS_FILE_NOT_FOUND = "JKS file is not present in the specified location";
    public static final String FILE_NOT_FOUND = "File is not found in the specified location";

    // RFC Error Codes for forming PKIFailureInfo, please use these while throwing new CMPException(String, message);
    public static final String BAD_MESSAGE_CHECK = "Invalid Message Type";
    public static final String TRANSACTION_ID_IN_USE = "TransactionId is in Use";
    public static final String HEADER_VERSION_ERROR = "Message header version error";

    public static final String CRL_VERSION_ERROR = "Invalid CRL Version";
    public static final String CRL_THISUPDATE_INVALID = "CRL is not Valid/Expired(Current date is before to thisUpdate)";
    public static final String CRL_NEXTUPDATE_INVALID = "CRL is not Valid/Expired(Current date is after to nextUpdate)";
    public static final String CERTIFICATE_REVOKED = "Certificate is Revoked";
    public static final String FAIL_TO_GENERATE_CRL = "Failed to read CRL";
    public static final String CRL_FORMAT_ERROR = "CRL not in proper format";
    public static final String CA_NOT_FOUND_FOR_CRL = "The CRL for issuer certificate is not present in trust store";

    public static final String IO_EXCEPTION = " IO exception Occured while byte conversion or reading input Stream.";
    public static final String KEY_NOT_RECOVERED = "Key can not be recovered";
    public static final String CERTIFICATE_ENCODING_ERROR = "Certificate encoding error";
    public static final String PROTECTION_ENCODING_ERROR = "Error Occured while building Response(Protected Part Encoding Failed)";
    public static final String CERTIFICATION_EXCEPTION = "EOF for the certificate doesnot exist";
    public static final String DB_EXCEPTION = "DB Error while performing CRUD operations";
    public static final String DB_EXCEPTION_AT_MANAGER = "DB Error while performing CRUD operations in pki-manager";
    public static final String TRANSACTION_ID_NOT_FOUND = "Message related to the Transaction is not found in db";
    public static final String IMPROPER_INITIAL_MESSAGE = "Request Message Type should be either IR or KUR";
    public static final String UNKNOWN_RESPONSE_TYPE = "Unknown Response Type from CA";
    public static final String CERTIFICATE_EXPIRED = "Certificate is Expired";
    public static final String CERTIFICATE_TYPE_NOT_SUPPORTED_BY_THE_PROVIDER = "Certificate not found";
    public static final String NO_TRUST_PROFILE_PRESENT = "Trust profile for the given ENtity CN is not present in the system";
    public static final String CSR_ENCODING_FAILED = "Error occurred while encoding the CSR";
    public static final String CSR_EXTENSIONS_ERROR = "CSR Extensions not present";

    public static final String UNSUPPORTED_ENCODING_EXCEPTION = "Unsupported Encoding Exception";
    // ERROR MESSAGEs for IAK
    public static final String MAC_NOT_INITIALIZED = "Mac is not initialized, please check.";
    public static final String INVALID_KEY_FOR_MAC = "Key is invalid for initializing MAC";
    public static final String IAK_AUTHENTICATION_FAILED = "IAK Validation Failed";

    // ErrorCodes for CMPv2Wrapper
    public static final String CERT_VERSION_ERROR = "X509v3 Certificates are only allowed, other versions are not acceptable";

    // Errorcodes for SCEP
    public static final String CERTIFICATE_PARSING_FAILED = "Failure in parsing Certificate";
    public static final String INVALID_CSR_ATRRIBUTE = "Invalid Atrribute in CSR";
    public static final String NO_SUCH_ALGORITHM = "No such Algorithm is defined";
    public static final String ALGORITHM_NOT_SUPPORTED = "Algorithm sent from node is not supported by PKI-system.";
    public static final String INVALID_SCEP_RESPONSE = "Invalid SCEP response ";

    // ErrorCodes to be passed over queue
    public static final String NOT_ABLE_TO_READ_SUBJECTDN = "Not able to read the SubjectDN/CN from request message.";
    public static final String ENTITY_DOES_NOT_EXISTS = "Entity doesn't exist";
    public static final String NOT_ABLE_TO_GENERATE_CERTIFICATE = "Not able to generate certificate for the Entity.";
    public static final String INVALID_CSR = "The given CSR in the Request message is not valid.";
    public static final String INVALID_ENTITY = "The given entity in the request in invalid.";
    public static final String CERTIFICATE_ALREADY_GENERATED = "Certificate has already been generated for the entity.";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate is not found for the entity.";
    public static final String UNABLE_TO_GENERATE_RESPONSE_MESSAGE = "Not able to generate response message.";

    public static final String OTP_NOT_FOUND = "OTP is not found in the CSR.";

    // Error Messages for revocation
    public static final String ROOT_CA_CANNOT_BE_REVOKED = "Root CA can not be revoked";
    public static final String ISSUER_NOT_FOUND = "Issuer details not found";
    public static final String INTERNAL_ERROR = "Exception occured while processing the request";
    public static final String CERTIFICATE_ALREADY_REVOKED = "Certificate already revoked";
    public static final String ENTITY_NOT_FOUND = "Entity not found";
    public static final String ISSUER_CERTIFICATE_ALREADY_REVOKED = "Issuer certificate is already revoked";

    public static final String CRL_EXPRIED = "CRL is Expried";
    public static final String CRL_CONVERSION_FAILED = "Failure in converting CRL";

    // Error Messages for KeyStore
    public static final String FORMAT_NOT_SUPPORTED = "Unsupporeted Format. Supported values are [JKS,P12,PEM,DER].";
    public static final String REVOCATION_FAILED = "Error Occured While Revoking Certificate";
    public static final String CONF_PARAM_NULL = "Invalid Path";
    public static final String CONFIG_MODEL_ERROR = "Configuration parameter is not modeled properly";

    // ErrorCodes for SecureCommunication
    public static final String FAILED_TO_UNMARSHALL = "Failed to unmarshal document to java XML object";
    public static final String FAILED_TO_MARSHALL = "Failed to marshal java XML object to document.";
    public static final String FAILED_TO_PARSE = "Failed to parse Signed xml ";
    public static final String FAILED_TO_SIGN = "Failed to sign the xml ";
    public static final String FAILED_TO_BUILD_DOCUMENT = "Failed to build XML DOM document.";
    public static final String INVALID_DIGITAL_SIGNATURE = "Invalid digital signature.";
    public static final String INVALID_CERTIFICATE_CHAIN = "Invalid certificate chain.";

}
