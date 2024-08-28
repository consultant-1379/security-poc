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
package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.*;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.*;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@RunWith(MockitoJUnitRunner.class)
public class CertHandlerTest {

    @InjectMocks
    CredMServiceWrapper mockWrapper;

    @Mock
    static CredMService mockRmiClient;

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.business.handlers.CertHandler#writeKeyAndCertificate(java.security.cert.Certificate, java.security.KeyPair, java.util.List)}
     * .
     */
    @Test
    public void testWriteKeyAndCertificate() {

        /*
         * Create KeyPair parameter
         */
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);
        final Certificate[] certChain = new Certificate[1];
        certChain[0] = cert;

        //final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        //ksInfoList.add(ksInfo);

        final CertHandler certHandler = new CertHandler();

        try {
            //certHandler.writeKeyAndCertificate(cert, keyPair, ksInfo);
            certHandler.writeKeyAndCertificate(certChain, keyPair, ksInfo);
        } catch (final CertHandlerException e) {

            e.printStackTrace();
            assertTrue("testWriteKeyAndCertificate: failed", false);
            File kfile = new File("/tmp/keyAndCertTest.jks");
            if(kfile.exists()) {
                assertTrue(kfile.delete());
            }
        }
    }

    @Test(expected = CertHandlerException.class)
    public void testWriteKeyAndCertificateFailedWrongPassword() throws CertHandlerException {

        /*
         * Create KeyPair parameter
         */
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);
        final Certificate[] certChain = new Certificate[1];
        certChain[0] = cert;

        //final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertTest.jks", "", "", null, CertificateFormat.JKS, "pipino", "Test");
        //ksInfoList.add(ksInfo);

        final CertHandler certHandler = new CertHandler();

        //certHandler.writeKeyAndCertificate(cert, keyPair, ksInfo);
        certHandler.writeKeyAndCertificate(certChain, keyPair, ksInfo);
    }

    @Test
    public void testGetSignedCertificate() {

        final CertHandler certHandler = new CertHandler();

        try {
            certHandler.getSignedCertificate(null, null, null, false, null);
            assertTrue("Exception not occurred", false);
        } catch (CertificateEncodingException | IssueCertificateException e) {
            assertTrue("Exception occurred", true);
        } catch (OtpExpiredException e) {
			assertTrue(false);
		} catch (OtpNotValidException e) {
			assertTrue(false);
		}
    }

    @Test
    public void testEmptyCertArray() {

        final CertHandler certHandler = new CertHandler();
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final PKCS10CertificationRequest csr = PrepareCertificate.prepareCsr(keyPair, "SHA256WithRSAEncryption");

        try {
            when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenReturn(new CredentialManagerX509Certificate[0]);

            certHandler.getSignedCertificate(mockWrapper, csr, "entityName", false, null);
            assertTrue("testEmptyCertArray: Exception not occurred", false);
        } catch (CertificateEncodingException | IssueCertificateException e) {
            assertTrue("testEmptyCertArray: Exception occurred", true);
        } catch (OtpExpiredException e) {
			assertTrue(false);
		} catch (OtpNotValidException e) {
			assertTrue(false);
		}
    }

    @Test
    public void testNullCertArray() {

        final CertHandler certHandler = new CertHandler();
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final PKCS10CertificationRequest csr = PrepareCertificate.prepareCsr(keyPair, "SHA256WithRSAEncryption");

        try {
            when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenReturn(null);

            certHandler.getSignedCertificate(mockWrapper, csr, "entityName", false, null);
            assertTrue("testNullCertArray: Exception not occurred", false);
        } catch (CertificateEncodingException | IssueCertificateException e) {
            assertTrue("testNullCertArray: Exception occurred", true);
        } catch (OtpExpiredException e) {
			assertTrue(false);
		} catch (OtpNotValidException e) {
			assertTrue(false);
		}
    }

    @Test
    public void testClearKeystoreFileCouple() {

        /*
         * Create KeyPair parameter
         */
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);
        final Certificate[] certChain = new Certificate[1];
        certChain[0] = cert;

        final KeystoreInfo ksInfo = new KeystoreInfo("", "/tmp/keyTest.key", "/tmp/certTest.pem", null, CertificateFormat.BASE_64, "keyStorePwd", "Test");

        final CertHandler certHandler = new CertHandler();

        try {
            certHandler.writeKeyAndCertificate(certChain, keyPair, ksInfo);
        } catch (final CertHandlerException e) {
            assertTrue("testClearKeystoreFileCouple: write failed", false);
        }

        try {
            certHandler.clearKeystore(ksInfo);
        } catch (final CertHandlerException e) {
            assertTrue("testClearKeystoreFileCouple: clear failed", false);
        }
        assertTrue("testClearKeystoreFileCouple: clear success", true);

    }
    
    @Test
    public void testNoCertDelete() {
        //create folder, create file, chmod folder, delete
        File lockDir = new File("/tmp/locktestNoCertDeleteDir");
        assertTrue(lockDir.mkdir());
        
        final KeystoreInfo ksLockInfo = new KeystoreInfo(lockDir.getAbsolutePath()+"/keystoreLock.jks", "", "", "", CertificateFormat.JKS, "keyStorePwd", "Test");
        File lockKS = new File(ksLockInfo.getKeyAndCertLocation());
        try {
            lockKS.createNewFile();
        } catch (IOException e2) {
            assertTrue(false);
        }
        assertTrue(lockKS.exists());
        final CertHandler certHandler = new CertHandler();
        assertTrue(lockDir.setReadable(true,true) && lockDir.setWritable(false,true) && lockDir.setExecutable(true,true));
        
        try {
            certHandler.clearKeystore(ksLockInfo);
            assertTrue(false);
        } catch (CertHandlerException e1) {
            assertTrue(true);
        }

        assertTrue(lockDir.setReadable(true,false) && lockDir.setWritable(true,false) && lockDir.setExecutable(true,false));
        assertTrue(lockKS.delete());
        assertTrue(lockDir.delete());
    }
}
