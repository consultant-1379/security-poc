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
package com.ericsson.oss.itpf.security.credmservice.api;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringAction;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;

public interface CredmControllerManager {
    CredentialManagerMonitoringResponse getMonitoring();

    CredentialManagerMonitoringResponse setMonitoring(CredentialManagerMonitoringAction action);
}
