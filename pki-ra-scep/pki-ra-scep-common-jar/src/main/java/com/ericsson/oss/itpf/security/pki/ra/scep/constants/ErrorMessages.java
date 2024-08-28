/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2013
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class contains all the errorMessages to enable the user to understand the exceptions clearly.
 *
 * @author xkarlak
 */

public class ErrorMessages {

    private ErrorMessages(){

    }

    public static final String REQUEST_PROCESS_FAILURE = "Unable to process the request";
    public static final String INVALID_CSR = "Invalid CSR in the Request message";
    public static final String UNAUTHORIZED = "Entity is unauthorized for requesting the certificate";
    public static final String CERTIFICATE_EXISTS = "Certificate already exist for requested entity";
    public static final String FAIL_TO_PROVIDE_CERTIFICATE = "Unable to provide the requested certificate";
    public static final String ENTITY_NOT_FOUND = "Requested entity is not found";
    public static final String INVALID_ENTITY = "Entity in the Request message is invalid";
    public static final String INVALID_OTP = "Invalid OTP in the CSR in the Request message";
    public static final String OTP_EXPIRED = "OTP provided in the Request message is expired";
    public static final String OTP_NOT_FOUND = "OTP is not found in the CSR";
    public static final String EMPTY_OPERATION = "Operation should not be empty in the URL";
    public static final String EMPTY_MESAGE = "Message should not be empty in the URL";
    public static final String UNSUPPORTED_SCEP_OPERATION = "Unsupported scep operation in the URL";
    public static final String RESPONSE_BUILD_FAILURE = "Failed to build the Response";
    public static final String INVALID_OPERATION = "Invalid SCEP operation";
    public static final String OPERATION_NOT_IMPLEMENTED = "The requested operation is not implemented";
    public static final String INVALID_CA_NAME = "Invalid CA name in the URL";
    public static final String GETCACERT_RESP_FAILURE = "Fail to create GetCaCert Response";
    public static final String GETCACERTCHAIN_RESP_FAILURE = "Fail to create GetCaCertChain Response";
    public static final String INVALID_MESSAGE_TYPE = "Invalid message type in the Request";
    public static final String MESSAGE_TYPE_NOT_IMPLEMENTED = "Message type not implemented";
    public static final String MESSAGE_TYPE_UNSUPPORTED = "Unsupported message type in the Request message";
    public static final String ATTRIBUTE_NOT_FOUND = " attribute not found in the Request message";
    public static final String INVALID_CONTENT_TYPE_FOR_ENVELOPEDATA = "Content type should be enveloped data in the Content Info";
    public static final String INVALID_CONTENT_TYPE_FOR_DATA = "Content Type should be data in the Content Info";
    public static final String FAIL_TO_DECRYPT = "Failed to decrypt message";
    public static final String NO_ASS0CIATED_PKCSREQ = "No associated PKCSReq is found";
    public static final String INVALID_REQUEST_MESSAGE = "Invalid request message";

    public static final String UNSUPPORTED_ENCRYPTION_ALGORITHM_IN_CMSSIGNEDDATA = "CmsEnvelopedData encyrption alogrithm is not supported";
    public static final String UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM_IN_RECIPIENTINFO = "RecipientInformation Key Encryption in Enveloped Data is not Supported";
    public static final String UNSUPPORTED_SIGNING_ALGORITHM = "UnSupported signature algorithm in signed data";
    public static final String SIGNING_ALG_NOT_FOUND = "Null value found for signing algorithm";
    public static final String EMPTY_KEYTRANSRECIPIENTID = "KeyTransRecipientId is null in RecipientInformationStore";
    public static final String EMPTY_ALGORITHM = " algorithm is empty";
    public static final String FAIL_TO_READ_ISSUER_AND_SUBJECT_NAME = "Failed to read Issuer and SubjectName from the Request Message";
    public static final String SIGNED_DATA_NOT_FOUND = "Signed data is not present";
    public static final String SIGNER_CERTIFICATE_NOT_FOUND = "Signer Certificate not found in SignedData of the Request message";
    public static final String SIGNER_INFO_NOT_FOUND = "SignerInformation is not present in the Request message";
    public static final String PENDING_RESP_FAILURE = "Failed to create CertResponse with pending status";
    public static final String FAILURE_RESP_FAILURE = "Failed to create CertResponse with failure status";
    public static final String SUCCESS_RESP_FAILURE = "Failed to create CertResponse with success status";
    public static final String CERT_RESP_FAILURE = "Failed to create CertResponse";

    public static final String TRANSACTION_ALREADY_EXIST = "PKCS Request with same Transaction Id with different Issuer and Subject name already exists";

    public static final String FAIL_TO_SIGN_REQUEST_MESSAGE = "Failed to sign the request message ";
    public static final String FAIL_TO_READ_CERTS_FROM_TRUSTSTORE = "Failed to read certificates from the trust store";

    public static final String CONFIGURATION_PROPERTY_VALUE_NULL = "Configuration Property Value is null";
    public static final String FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_DB_CLEANUP_SCHEDULER_TIME_VALUE = "Configuration Property is not found with name scepDBCleanupSchedulerTime. Could not start PKIRASCEP DB cleanup scheduler job.";
    public static final String FAILED_TO_READ_CONFIGURATION_PARAMETER_SCEP_REQUEST_RECORD_PURGE_PERIOD_VALUE = "Configuration Property is not found with name scepRequestRecordPurgePeriod. Could not start PKIRASCEP DB cleanup scheduler job.";
    public static final String PREVIOUS_TIMER_IS_ALREADY_RUNNING = "Error occured while triggering timeout for SCEP DBCleanup job. Previous timer DBCleanupSchedulerInfo is already running and waiting for next time out";
}
