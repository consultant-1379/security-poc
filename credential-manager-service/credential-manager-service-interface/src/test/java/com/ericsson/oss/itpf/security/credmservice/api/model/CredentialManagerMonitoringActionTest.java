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

public class CredentialManagerMonitoringActionTest {

    @Test
    public void test() {
        final CredentialManagerMonitoringAction label = CredentialManagerMonitoringAction.fromString("disable");
        final String returnedString = CredentialManagerMonitoringAction.DISABLE.getText();
        assertTrue(label == CredentialManagerMonitoringAction.DISABLE);
        assertTrue(returnedString.equals("disable"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeTest() {
        try {
            CredentialManagerMonitoringAction.fromString("notfound");
        } catch (final Exception ex) {
            System.out.println(ex.getMessage());
            throw ex;
        }
    }
}
