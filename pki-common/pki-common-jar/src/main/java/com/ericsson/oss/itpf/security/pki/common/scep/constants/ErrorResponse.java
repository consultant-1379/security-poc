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
package com.ericsson.oss.itpf.security.pki.common.scep.constants;

/**
 * ErrorResponse class will provide ErrorCodes which will be mapped to the Exceptions raised during processing of CSR of SCEP Client.
 * 
 * @author xananer
 */

public enum ErrorResponse {
    BAD_REQUEST("BAD_REQUEST"), UNAUTHORIZED("UNAUTHORIZED"), INTERNAL_ERROR("INTERNAL_ERROR"), INVALID_ENTITY("INVALID_ENTITY"), ENTITY_NOT_FOUND("ENTITY_NOT_FOUND"), INVALID_OTP("INVALID_OTP"), OTP_EXPIRED(
            "OTP_EXPIRED"), INVALID_CSR("INVALID_CSR"), CERTIFICATE_EXISTS("CERTIFICATE_EXISTS"), CERTIFICATE_ENCODING_ERROR("CERTIFICATE_ENCODING_ERROR"), OTP_NOT_FOUND("OTP_NOT_FOUND"), AlGORITHM_NOT_FOUND(
            "AlGORITHM_NOT_FOUND"), INVALID_CA("INVALID_CA"),SIGNATURE_VERIFICATION_FAILED("SIGNATURE_VERIFICATION_FAILED");

    /**
     * ResponseError is the FailureInfo to be sent in the ScepResponseMessage
     */
    String error;

    ErrorResponse(final String value) {
        this.error = value;
    }

    /**
     * @return the error
     */
    public String getValue() {
        return error;
    }

    @Override
    public String toString() {
        return name();
    }
}