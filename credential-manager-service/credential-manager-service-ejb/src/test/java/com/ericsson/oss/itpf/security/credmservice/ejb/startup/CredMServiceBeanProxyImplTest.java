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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCheckException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerDbUpgradeException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.util.CredMPkiConfInitializer;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CredMServiceSelfCredentialsManager.class)
public class CredMServiceBeanProxyImplTest {

    @Mock
    CredMServiceSelfCredentialsManager credMServiceSelfCredentialsManager;
    
    @Mock
    CredMPkiConfInitializer credMPkiConfInitializer;
    
    @InjectMocks
    CredMServiceBeanProxyImpl credMServiceBeanProxyImpl;

    @Test
    public void testCheckJBossCredentials() throws CredentialManagerCheckException, CredentialManagerStartupException {
        PowerMockito.mockStatic(CredMServiceSelfCredentialsManager.class);
        PowerMockito.when(CredMServiceSelfCredentialsManager.checkCertificateValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkJbossEntityReissueState()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrustValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrusts()).thenReturn(true);

        credMServiceBeanProxyImpl.checkJBossCredentials();
    }

    @Test
    public void testCheckJBossCredentialsExpired() throws CredentialManagerCheckException, CredentialManagerStartupException {
        PowerMockito.mockStatic(CredMServiceSelfCredentialsManager.class);
        PowerMockito.when(CredMServiceSelfCredentialsManager.checkCertificateValidity()).thenReturn(false);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkJbossEntityReissueState()).thenReturn(true);

        try {
            credMServiceBeanProxyImpl.checkJBossCredentials();
            assertFalse(true);
        } catch (final CredentialManagerCheckException e) {
            assertTrue(e.getMessage().contains("Expired certificates"));
        }
    }

    @Test
    public void testCheckJBossCredentialsReissue() throws CredentialManagerCheckException, CredentialManagerStartupException {
        PowerMockito.mockStatic(CredMServiceSelfCredentialsManager.class);
        PowerMockito.when(CredMServiceSelfCredentialsManager.checkCertificateValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkJbossEntityReissueState()).thenReturn(false);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrustValidity()).thenReturn(true);

        try {
            credMServiceBeanProxyImpl.checkJBossCredentials();
            assertFalse(true);
        } catch (final CredentialManagerCheckException e) {
            assertTrue(e.getMessage().contains("Certificate has to be reissued"));
        }
    }

    @Test
    public void testCheckTrusts() throws CredentialManagerCheckException, CredentialManagerStartupException {
        PowerMockito.mockStatic(CredMServiceSelfCredentialsManager.class);
        PowerMockito.when(CredMServiceSelfCredentialsManager.checkCertificateValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkJbossEntityReissueState()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrustValidity()).thenReturn(false);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrusts()).thenReturn(true);

        try {
            credMServiceBeanProxyImpl.checkJBossCredentials();
            assertFalse(true);
        } catch (final CredentialManagerCheckException e) {
            assertTrue(e.getMessage().contains("Truststore not present"));
        }
    }

    @Test
    public void testCheckTrustValidity() throws CredentialManagerCheckException, CredentialManagerStartupException {
        PowerMockito.mockStatic(CredMServiceSelfCredentialsManager.class);
        PowerMockito.when(CredMServiceSelfCredentialsManager.checkCertificateValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkJbossEntityReissueState()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrustValidity()).thenReturn(true);
        PowerMockito.when(credMServiceSelfCredentialsManager.checkTrusts()).thenReturn(false);

        try {
            credMServiceBeanProxyImpl.checkJBossCredentials();
            assertFalse(true);
        } catch (final CredentialManagerCheckException e) {
            assertTrue(e.getMessage().contains("Invalid trusts"));
        }
    }
    
    @Test
    public void testgenerateJBossCredentials() throws CredentialManagerStartupException {
        credMServiceBeanProxyImpl.generateJBossCredentials();
    }
    
    @Test
    public void testCvnCheckAndpkiDbUpgrade() {
    	
        try {
            credMServiceBeanProxyImpl.checkDbCvnStatus();
            credMServiceBeanProxyImpl.pkiDbUpgrade();
            assertTrue(true);
        } catch (CredentialManagerDbUpgradeException e) {
            e.printStackTrace();
            assertTrue(false); 
        }
    }

}
