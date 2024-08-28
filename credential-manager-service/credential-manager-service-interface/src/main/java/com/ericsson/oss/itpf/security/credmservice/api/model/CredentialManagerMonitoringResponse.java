/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;

public class CredentialManagerMonitoringResponse implements Serializable{

    private static final long serialVersionUID = 2149412851609932841L;
    private final int httpStatus;
    private final CredentialManagerMonitoringStatus monitoringStatus;

    /**
     * Class to incapsulate a http monitoring command response message received from Credential Manager Controller
     *
     * @param httpStatus
     *            The HTTP status code of the response received
     * @param monitoringStatus
     *            The monitoring status value contained in the HTTP response message
     */
    public CredentialManagerMonitoringResponse(final int httpStatus, final CredentialManagerMonitoringStatus monitoringStatus) {
        this.httpStatus = httpStatus;
        this.monitoringStatus = monitoringStatus;
    }

    /**
     * @return the httpStatus
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    /**
     * @return the monitoringStatus
     */
    public CredentialManagerMonitoringStatus getMonitoringStatus() {
        return monitoringStatus;
    }
}
