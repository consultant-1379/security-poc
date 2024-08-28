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
 * ResponseStatus Class will provide the status of the certificate request processing and Certificate generation which will be sent in the ScepResponseMessage.
 * 
 * @author xananer
 */

public enum ResponseStatus {
    SUCCESS(0), FAILURE(2), PENDING(3);

    /**
     * responseStatus is the status to be sent in the ScepResponseMessage
     */
    int status;

    ResponseStatus(final int value) {
        this.status = value;
    }

    /**
     * @return the responseStatus
     */
    public int getStatus() {
        return status;
    }

    /**
     * 
     * @param value
     * @return ResponseStatus
     */
    public static ResponseStatus getNameByValue(final int value) {
        for (final ResponseStatus responseStatus : ResponseStatus.values()) {
            if (responseStatus.status == value) {
                return responseStatus;
            }
        }
        return null;
    }

    /**
     * {@inheritDoc}
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return name();
    }
}
