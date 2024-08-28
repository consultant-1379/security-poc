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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.util;

/**
 * Class for representing error messages for Revocation Service.
 * 
 */
public class ErrorMessages {

    // Error Messages
    public static final String ROOT_CA_CANNOT_BE_REVOKED = "Root CA can not be revoked";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate not found";
    public static final String INVALID_CERTIFICATE = "Invalid certificate";
    public static final String ISSUER_NOT_FOUND = "Issuer details not found";
    public static final String INTERNAL_ERROR = "Exception occured while processing the request";
    public static final String CERTIFICATE_ALREADY_REVOKED = "Certificate already revoked";
    public static final String ENTITY_NOT_FOUND = "Entity not found";
    public static final String ISSUER_CERTIFICATE_ALREADY_REVOKED = "Issuer certificate is already revoked";
    public static final String CERTIFICATE_CONVERSION_ERROR = "Problem with certificate converter";
    public static final String ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED = "Root CA cannot be revoked. Root CA is Sub CA of External CA. Please contact external CA administrator for revocation of this Root CA";

}
