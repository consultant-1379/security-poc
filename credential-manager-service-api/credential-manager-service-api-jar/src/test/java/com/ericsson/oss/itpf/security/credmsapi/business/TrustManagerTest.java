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
package com.ericsson.oss.itpf.security.credmsapi.business;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CertHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.TrustHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;

@RunWith(MockitoJUnitRunner.class)
public class TrustManagerTest {

    String xmlSubject = "O=OpenDJ, CN=Administrator";

    @InjectMocks
    CredMServiceWrapper mockWrapper;
    @Mock
    static CredentialManagerServiceRestClient mockRestCLient;
    @Mock
    static CredMService mockRmiClient;

    String entityProfileName = "p";

    @Test
    public void testGetTrustMock() {

        final TrustManager trustManager = new TrustManager(this.mockWrapper);
        final CredentialManagerTrustMaps caMapChainB = PrepareCertificate.prepareTrust();
        // test get trust
        try {
            when(mockRmiClient.getTrustCertificates(this.entityProfileName)).thenReturn(caMapChainB);
            trustManager.retrieveTrust(this.entityProfileName);
            assertTrue("trustMap incomplete", !trustManager.getTrustMaps().getInternalCATrustMap().isEmpty() && !trustManager.getTrustMaps().getExternalCATrustMap().isEmpty());
        } catch (final Exception e) {
            assertTrue("testGetTrust: exception occurred", false);
            //e.printStackTrace();
            return;
        }
        assertTrue("testGetTrust: ok", true);
    }

    @Test
    public void testGetTrustExcMock() {

        final TrustManager trustManager = new TrustManager(this.mockWrapper);
        //final CredentialManagerTrustMaps caMapChainB = PrepareCertificate.prepareTrust();
        // test get trust
        try {
            when(mockRmiClient.getTrustCertificates(this.entityProfileName)).thenReturn(null);
            trustManager.retrieveTrust(this.entityProfileName);
            assertTrue("getTrust exception not occurred", false);
        } catch (final Exception e) {
            assertTrue("testGetTrust: exception occurred", true);
            //e.printStackTrace();
        }
    }

    @Test
    public void testHandlerGetTrustMock() {

        final TrustHandler trustHandler = new TrustHandler();
        final CredentialManagerTrustMaps caMapChainB = PrepareCertificate.prepareTrust();
        CredentialManagerTrustMaps caMap = null;
        // test get trust
        try {
            when(mockRmiClient.getTrustCertificates(this.entityProfileName)).thenReturn(caMapChainB);
            caMap = trustHandler.getTrustCertificates(this.entityProfileName, this.mockWrapper);
        } catch (final Exception e) {
            assertTrue("testGetTrust: exception occurred", false);
            //e.printStackTrace();
            return;
        }
        assertTrue("testGetTrust: ok", (!caMap.getInternalCATrustMap().isEmpty()) && !caMap.getExternalCATrustMap().isEmpty());
    }

    @Test
    public void testWriteTrust() {

        final TrustManager trustManager = new TrustManager(null);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();
        trustManager.setTrustMaps(caMaps);
        assertTrue("testWriteTrust getCaMapChain", !trustManager.getTrustMaps().getInternalCATrustMap().isEmpty() && !trustManager.getTrustMaps().getExternalCATrustMap().isEmpty());

        /**
         * create tsInfoList (EXTERNAL trust only)
         */
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststoreTest.jks", "", TrustFormat.JKS, "keyStorePwd", "Test", TrustSource.EXTERNAL);
        tsInfoList.add(tsInfo);

        // test write
        try {
            trustManager.writeTrust(tsInfoList);
        } catch (final Exception e) {
            assertTrue("testWriteTrust: failed", false);
            return;
        }

        final File file = new File("/tmp/truststoreTest.jks");
        assertTrue("testWriteTrust: not OK", file.exists());
        file.delete();
    }

    @Test
    public void testWriteTrustNullMapExc() {

        final TrustManager trustManager = new TrustManager(null);

        /**
         * create tsInfoList (EXTERNAL trust only)
         */
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststoreTest.jks", "", TrustFormat.JKS, "keyStorePwd", "Test", TrustSource.EXTERNAL);
        tsInfoList.add(tsInfo);

        // test write
        try {
            trustManager.writeTrust(tsInfoList);
            assertTrue("Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception occurred", true);
        }
    }

    @Test
    public void testWriteTrustWriteExc() {

        final TrustManager trustManager = new TrustManager(null);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();
        trustManager.setTrustMaps(caMaps);
        assertTrue("testWriteTrust getCaMapChain", !trustManager.getTrustMaps().getInternalCATrustMap().isEmpty() && !trustManager.getTrustMaps().getExternalCATrustMap().isEmpty());

        /**
         * create tsInfoList (EXTERNAL trust only)
         */
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/truststoreTest.jks", "", TrustFormat.JKS, "keyStorePwd", "Test", null);
        tsInfoList.add(tsInfo);

        // test write
        try {
            trustManager.writeTrust(tsInfoList);
            assertTrue("Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception occurred", true);
        }
    }

    @Test
    public void testCleanTruststore() {

        final TrustManager trustManager = new TrustManager(null);

        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/TruststoreTest.jks", null, TrustFormat.JKS, "keyStorePwd", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        // prepare the keystore
        final KeyPair keyPair = PrepareCertificate.createKeyPair();
        final X509Certificate cert = PrepareCertificate.prepareCertificate(keyPair);
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/TruststoreTest.jks", "", "", null, CertificateFormat.JKS, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);
        final CertHandler certHandler = new CertHandler();
        try {
            certHandler.writeKeyAndCertificate(new Certificate[] { cert }, keyPair, ksInfo);
        } catch (final CertHandlerException e) {
            //e.printStackTrace();
            assertTrue("testWriteKeyAndCertificate: failed", false);
        }
        // add trust data
        final TrustHandler trustHandler = new TrustHandler();
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            //e.printStackTrace();
            assertTrue("writeTrustCertificates: TrustHandlerException", false);
        }

        final File file = new File("/tmp/TruststoreTest.jks");
        assertTrue("Truststore not created", file.exists());

        // now the file has 2 entries: cert (alias = "test") and trust (alias = "myAlias")

        // test (ts = ks)
        trustManager.clearTruststores(tsInfoList);
        assertTrue("testCleanTruststore (ts = ks): failed", file.exists());

        // at this point the trust entry has been deleted

        trustManager.clearTruststores(tsInfoList);

        // trying to remove "myAlias", the entry is not deleted
        assertTrue("testCleanTruststore (ts != ks): failed", file.exists());

        // change alias to allow deletion of the entry
        tsInfoList.get(0).setAlias("Test");
        trustManager.clearTruststores(tsInfoList);
        // now the file must be deleted
        assertTrue("testCleanTruststore (ts != ks): failed", file.length() < 100);
        file.delete();

    }

} // end of TrustManagerTest
