/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;

public class CredentialManagerRevocationUtilsTest {
    
    @Test
    public void convertRevocationReasonTest() {
        
        CredentialManagerRevocationReason cmRevocationReason;
        CrlReason crlReason;
        CredentialManagerRevocationUtils covCMRev = new CredentialManagerRevocationUtils();
        assertTrue(covCMRev != null);
        
        crlReason = CrlReason.A_A_COMPROMISE;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.AA_COMPROMISE));
        
        crlReason = CrlReason.AFFILIATION_CHANGED;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.AFFILIATION_CHANGED));
        
        crlReason = CrlReason.CA_COMPROMISE;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.CA_COMPROMISE));
    
        crlReason = CrlReason.CERTIFICATE_HOLD;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.CERTIFICATE_HOLD));
        
        crlReason = CrlReason.CESSATION_OF_OPERATION;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.CESSATION_OF_OPERATION));
    
        crlReason = CrlReason.KEY_COMPROMISE;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.KEY_COMPROMISE));
        
        crlReason = CrlReason.PRIVILEGE_WITHDRAWN;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.PRIVILEGE_WITHDRAWN));
        
        crlReason = CrlReason.REMOVE_FROM_CRL;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.REMOVE_FROM_CRL));
    
        crlReason = CrlReason.SUPERSEDED;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.SUPERSEDED));
        
        crlReason = CrlReason.UNSPECIFIED;
        cmRevocationReason = CredentialManagerRevocationUtils.convertRevocationReason(crlReason);
        assertTrue(cmRevocationReason.equals(CredentialManagerRevocationReason.UNSPECIFIED));

    }

}
