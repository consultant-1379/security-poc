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

import static org.junit.Assert.assertTrue;

import org.apache.http.HttpStatus;
import org.junit.Test;

public class CredentialManagerMonitoringResponseTest {

    @Test
    public void test() {
        final CredentialManagerMonitoringResponse monitoringResponse = new CredentialManagerMonitoringResponse(HttpStatus.SC_OK, CredentialManagerMonitoringStatus.ENABLING);
        assertTrue(monitoringResponse.getHttpStatus() == HttpStatus.SC_OK);
        assertTrue(monitoringResponse.getMonitoringStatus() == CredentialManagerMonitoringStatus.ENABLING);
    }

}
