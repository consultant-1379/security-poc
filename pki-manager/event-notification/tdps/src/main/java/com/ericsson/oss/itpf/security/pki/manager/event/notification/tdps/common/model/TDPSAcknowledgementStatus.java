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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.model;

/**
 * This is a local ENum class which is maps TDPSResponseType to various acknowledgement status.
 * 
 * @author tcsdemi
 *
 */
public enum TDPSAcknowledgementStatus {
    SUCCESS("Success"), FAILURE("Failure");

    private String value;

    private TDPSAcknowledgementStatus(final String status) {
        this.value = status;

    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}