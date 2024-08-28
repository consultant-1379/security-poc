/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.api.exception;

/**
 * Class to Encapsulate all Credential Manager Error Codes and their Suggested Solutions
 */
public class CredentialManagerErrorCodes {
    public static final String PLEASE_CHECK_ONLINE_HELP_FOR_CORRECT_SYNTAX = "Please check Online Help for correct syntax.";
    public static final String SUGGESTED_SOLUTION_CONSULT_ERROR_LOGS =
            "An error occurred while executing the command on the system. Consult the error and command logs for more information.";
    public static final String SYNTAX_ERROR = "Command syntax error";
    public static final String UNEXPECTED_INTERNAL_ERROR = "Unexpected Internal Error";
    public static final String INVALID_ARGUMENT = "Invalid Argument";
    public static final String CERTIFICATE_ENCODING_ERROR = "Certificate encoding error";
    public static final String ENTITY_INVALID = "Invalid Entity";
    public static final String ENTITY_NOT_FOUND = "Entity Not Found";
    public static final String PROFILE_INVALID = "Invalid Profile";
    public static final String PROFILE_NOT_FOUND = "Entity Not Found";
    public static final String CERTIFICATE_SERVICE_ERROR = "Certificate service error";
    public static final String CA_NOT_FOUND = "Certificate Authority does not exist";
    public static final String SN_NOT_FOUND = "Serial-Number does not exist for this Certificate Authority";
    public static final String KEY_SIZE_NOT_SUPPORTED = "Key Size not supported";
    public static final String ALGORITHM_NOT_SUPPORTED = "Signature Algorithm not supported";
    public static final String CRL_SERVICE_ERROR = "CRL Service Error";
    public static final String CERTIFICATE_EXISTS = "Certificate already exists for the Entity";
    public static final String CERITIFICATE_GENERATION_ERROR = "Error during Certificate generation";
    public static final String INVALID_CSR = "Invalid CSR";
    public static final String INVALID_CA = "Invalid CA";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate Not Found";
    public static final String OTP_EXPIRED = "One Time Password (OTP) Expired";
    public static final String OTP_INVALID = "One Time Password (OTP) Invalid";
    public static final String EXPIRED_CERTIFICATE = "The certificate is expired";
    public static final String REVOKED_CERTIFICATE = "The certificate is already revoked";
    public static final String INVALID_CERT_STATUS = "The Certificate Status is invalid";
}
