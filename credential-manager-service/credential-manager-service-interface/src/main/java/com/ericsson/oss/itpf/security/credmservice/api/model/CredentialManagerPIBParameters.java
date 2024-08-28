/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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
import java.util.Arrays;
import java.util.List;


public class CredentialManagerPIBParameters implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private int serviceCertAutoRenewalTimer = 0;
    private boolean serviceCertAutoRenewalEnabled = true;
    private String serviceCertAutoRenewalWarnings = "0";
    public int getServiceCertAutoRenewalTimer() {
        return serviceCertAutoRenewalTimer;
    }
    public void setServiceCertAutoRenewalTimer(int serviceCertAutoRenewalTimer) {
        this.serviceCertAutoRenewalTimer = serviceCertAutoRenewalTimer;
    }
    public boolean isServiceCertAutoRenewalEnabled() {
        return serviceCertAutoRenewalEnabled;
    }
    public void setServiceCertAutoRenewalEnabled(boolean serviceCertAutoRenewalEnabled) {
        this.serviceCertAutoRenewalEnabled = serviceCertAutoRenewalEnabled;
    }
    public String getServiceCertAutoRenewalWarnings() {
        return serviceCertAutoRenewalWarnings;
    }
    public void setServiceCertAutoRenewalWarnings(String serviceCertAutoRenewalWarnings) {
        this.serviceCertAutoRenewalWarnings = serviceCertAutoRenewalWarnings;
    }
    
    public List<String> getServiceCertAutoRenewalWarningsList() {
        return Arrays.asList( this.serviceCertAutoRenewalWarnings.split(","));
    }
}
