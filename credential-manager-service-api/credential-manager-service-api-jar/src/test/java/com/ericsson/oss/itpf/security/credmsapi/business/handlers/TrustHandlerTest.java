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

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

import java.io.File;
import java.security.cert.Certificate;
import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialWriterFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.JKSReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@RunWith(MockitoJUnitRunner.class)
public class TrustHandlerTest {

    @InjectMocks
    CredMServiceWrapper mockWrapper;
    @Mock
    static CredentialManagerServiceRestClient mockRestCLient;
    @Mock
    static CredMService mockRmiClient;

    String entityProfileName = "p";

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.business.handlers.TrustHandler#writeTrustCertificates(boolean, java.util.List, java.util.Map)} .
     */

    @Test
    public void testHandlerGetTrustCertificatestMock() {

        final TrustHandler trustHandler = new TrustHandler();
        final CredentialManagerTrustMaps caMapChainB = PrepareCertificate.prepareTrust();

        CredentialManagerTrustMaps caMaps = null;
        // test get trust
        try {
            when(mockRmiClient.getTrustCertificates(this.entityProfileName)).thenReturn(caMapChainB);
            caMaps = trustHandler.getTrustCertificates(this.entityProfileName, this.mockWrapper);
        } catch (final Exception e) {
            assertTrue("testGetTrust: exception occurred", false);
            e.printStackTrace();
            return;
        }
        assertTrue("testGetTrust: not ok", (!caMaps.getInternalCATrustMap().isEmpty() && !caMaps.getExternalCATrustMap().isEmpty()));
    }

    @Test
    public void testHandlerGetTrustCertificatesServiceNull() {

        final TrustHandler trustHandler = new TrustHandler();

        // test get trust
        try {
            trustHandler.getTrustCertificates(this.entityProfileName, null);
            assertTrue("testGetTrust: Exception not occurred", false);
        } catch (final TrustHandlerException e) {
            assertTrue("testGetTrust: Exception occurred", true);
        }
    }

    @Test
    public void testWriteJKSTrustCertificates() {

        /**
         * Trust store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/testTrust.jks", null, TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * Key&Cert store
         */
        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/testKeyCert.jks", null, null, null, CertificateFormat.JKS, "", "alias");
        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        ksInfoList.add(ksInfo);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }

        final File file = new File("/tmp/testTrust.jks");
        assertTrue("file not written", file.exists());
        final long modified = file.lastModified(); // back in time of 2 seconds!

        try {
            Thread.sleep(1000);
        } catch (final InterruptedException e) {
            e.printStackTrace();
            assertTrue("sleep failed", false);
        }
        // overwrite file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }
        assertTrue("file not written", file.lastModified() != modified);
        file.delete();
    }

    @Test
    public void testWriteJKSTrustCertificatesChain() {

        /**
         * Trust store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/testTrust.jks", null, TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrustChain();

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }

        final File file = new File("/tmp/testTrust.jks");
        assertTrue("file not written", file.exists());
        file.delete();
    }

    @Test
    public void testWriteJKSTrustWithInactiveCertificates() throws StorageException {

        /**
         * Trust store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/testTrust.jks", null, TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrustWithInactive();
        final Collection<CredentialManagerX509Certificate>  setcertificate = caMaps.getInternalCATrustMap().get("pippo").getCertChainSerializable();
        final Iterator<CredentialManagerX509Certificate> iterator = setcertificate.iterator();
        final CredentialManagerX509Certificate x509Certificate = iterator.next();
        final String serialNumber= String.valueOf(x509Certificate.retrieveCertificate().getSerialNumber());

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }

        final File file = new File("/tmp/testTrust.jks");
        assertTrue("file not written", file.exists());
        final JKSReader reader = new JKSReader("/tmp/", "/tmp/testTrust.jks", "", StorageConstants.JKS_STORE_TYPE);

        final Certificate certificate = reader.getCertificate("myalias_cn=cn_"+serialNumber);
        assertNotNull("Entry not found", certificate);
        file.delete();
    }

    @InjectMocks
    CredentialWriterFactory cmFactory;
    @Mock
    CredentialWriter writer;

    @Test
    public void testWriteTrustCertificatesExc() {

        /**
         * Trust store (not existing directory)
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/pluto/testTrust.jks", null, TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
            assertTrue("testWriteTrustCertificatesExc: Exception not originated", false);
        } catch (final TrustHandlerException e) {
            assertTrue("testWriteTrustCertificatesExc: Exception originated", true);
        }

    }

    @Test
    public void testClearTruststoreDir() {

        /**
         * Trust store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo(null, "/tmp/testCert", TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * create directory
         */
        final File dir = new File("/tmp/testCert");
        dir.mkdir();

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }

        assertTrue("folder is empty", (dir.listFiles().length > 0));

        try {
            trustHandler.clearTruststore(tsInfo);
        } catch (final TrustHandlerException e) {
            assertTrue("Exception not expected", false);
        }

        assertTrue("folder not empty", (dir.listFiles().length == 0));
        dir.delete();

    }

    @Test
    public void testClearTruststoreExc() {

        /**
         * Trust store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/testTrust.jks", null, TrustFormat.JKS, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * CA Map Chain
         */
        final CredentialManagerTrustMaps caMaps = PrepareCertificate.prepareTrust();

        final TrustHandler trustHandler = new TrustHandler();

        // new file
        try {
            trustHandler.writeTrustCertificates(tsInfoList.get(0), caMaps);
        } catch (final TrustHandlerException e) {
            e.printStackTrace();
            assertTrue("writeTrustCertificates(JKS): TrustHandlerException", false);
        }

        final File file = new File("/tmp/testTrust.jks");
        assertTrue("file not written", file.exists());

        tsInfo.setAlias(null); // force wrong condition

        try {
            trustHandler.clearTruststore(tsInfo);
            assertTrue("Exception not occurred", false);
        } catch (final TrustHandlerException e) {
            assertTrue("Exception expected", true);
        }

        file.delete(); // delete empty file
    }
} // end of file
