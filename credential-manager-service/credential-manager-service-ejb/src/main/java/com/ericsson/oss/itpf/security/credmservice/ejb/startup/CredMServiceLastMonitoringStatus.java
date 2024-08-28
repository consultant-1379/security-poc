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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringStatus;

@ApplicationScoped
public class CredMServiceLastMonitoringStatus {

    private CredentialManagerMonitoringStatus lastMonitoringStatus = CredentialManagerMonitoringStatus.ENABLED;

    /**
     * @return the lastMonitoringStatus
     */
    public CredentialManagerMonitoringStatus getLastMonitoringStatus() {
        return lastMonitoringStatus;
    }

    /**
     * @param lastMonitoringStatus
     *            the lastMonitoringStatus to set
     */
    public void setLastMonitoringStatus(final CredentialManagerMonitoringStatus lastMonitoringStatus) {
        this.lastMonitoringStatus = lastMonitoringStatus;
    }

}
