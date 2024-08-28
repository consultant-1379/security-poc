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

import org.junit.Test;

public class CredentialManagerMonitoringStatusTest {

    @Test
    public void test() {
        final CredentialManagerMonitoringStatus label = CredentialManagerMonitoringStatus.fromString("Disabled");
        final String returnedString = CredentialManagerMonitoringStatus.DISABLED.getText();
        assertTrue(label == CredentialManagerMonitoringStatus.DISABLED);
        assertTrue(returnedString.equals("Disabled"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeTest() {
        try {
            CredentialManagerMonitoringStatus.fromString("notfound");
        } catch (final Exception ex) {
            System.out.println(ex.getMessage());
            throw ex;
        }
    }
}
