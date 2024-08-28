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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.*;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;

@RunWith(MockitoJUnitRunner.class)
public class CrlHandlerTest {

    @InjectMocks
    CredMServiceWrapper mockWrapper;

    @Mock
    static CredMService mockRmiClient;

    @Test
    public void testGetTrustCRLsServiceNull() {

        final CrlHandler crlHandler = new CrlHandler();

        try {
            crlHandler.getTrustCRLs(null, "entityProfileName");
            assertTrue("testGetTrustCRLsServiceNull: Exception not originated", false);
        } catch (final TrustHandlerException e) {
            assertTrue("testGetTrustCRLsServiceNull: Exception originated", true);
        }
    }

    @Test
    public void testGetTrustCRLsMock() {

        final CrlHandler crlHandler = new CrlHandler();

        try {
            when(mockRmiClient.getCRLs(Matchers.anyString(), Matchers.anyBoolean())).thenThrow(new CredentialManagerInvalidArgumentException());
            crlHandler.getTrustCRLs(mockWrapper, "entityProfileName");
            assertTrue("testGetTrustCRLsMock: Exception not originated", false);
        } catch (final TrustHandlerException e) {
            assertTrue("testGetTrustCRLsMock: Exception originated", true);
        }

    }

    @Test
    public void testWriteTrustCrlExc() {

        /**
         * Trust store (not existing directory)
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/pluto/testCrl.crl", null, TrustFormat.BASE_64, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * CRL Map Chain
         */
        final CredentialManagerCrlMaps crlMaps = PrepareCertificate.generateCrl();

        final CrlHandler crlHandler = new CrlHandler();

        // new file
        try {
            crlHandler.writeTrustCRLs(tsInfo, crlMaps);
            assertTrue("testWriteTrustCrlExc: Exception not originated", false);
        } catch (final TrustHandlerException e) {
            assertTrue("testWriteTrustCrlExc: Exception originated", true);
        }
    }

    @Test
    public void testClearCrlstoreDir() {

        /**
         * Crl store
         */
        final TrustStoreInfo tsInfo = new TrustStoreInfo(null, "/tmp/testCert", TrustFormat.BASE_64, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);

        /**
         * create directory
         */
        final File dir = new File("/tmp/testCert");
        dir.mkdir();

        /**
         * CRL Map Chain
         */
        final CredentialManagerCrlMaps crlMaps = PrepareCertificate.generateCrl();

        final CrlHandler crlHandler = new CrlHandler();

        // new file
        try {
            crlHandler.writeTrustCRLs(tsInfo, crlMaps);
        } catch (final TrustHandlerException e) {
            assertTrue("testClearCrlstoreExc(JKS): TrustHandlerException", false);
        }

        assertTrue("folder is empty", (dir.listFiles().length > 0));

        try {
            crlHandler.clearCrlStore(tsInfo);
        } catch (final TrustHandlerException e) {
            assertTrue("Exception occurred", false);
        }

        assertTrue("folder not empty", (dir.listFiles().length == 0));
        dir.delete();
    }

    @Test
    public void testNoWrite() throws TrustHandlerException {
        final TrustStoreInfo tsInfo = new TrustStoreInfo(null, "/tmp/testCert", TrustFormat.BASE_64, "", "myAlias", TrustSource.INTERNAL);
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        tsInfoList.add(tsInfo);
        final CrlHandler crlHandler = new CrlHandler();
        CredentialManagerCrlMaps crlMaps = new CredentialManagerCrlMaps();
        crlHandler.writeTrustCRLs(tsInfo, crlMaps);
        CredentialManagerCrlMaps crlMaps1 = null;
        try {
            crlHandler.writeTrustCRLs(tsInfo, crlMaps1);
            assertTrue(false);
        } catch(TrustHandlerException e) {
            assertTrue(e.getMessage().contains("writeTrustCRLs: crl maps cannot be null"));
        }
    }
    
    @Test
    public void testNoCrlDelete() {
        //create folder, create file, chmod folder, delete
        File lockDir = new File("/tmp/locktestNoCrlDeleteDir");
        lockDir.mkdir();
        final TrustStoreInfo crlLockInfo = new TrustStoreInfo("/tmp/locktestNoCrlDeleteDir/testLockCRL", null, TrustFormat.BASE_64, "pass", "myAlias", TrustSource.INTERNAL);
        File lockCrl = new File(crlLockInfo.getTrustFileLocation());
        try {
            lockCrl.createNewFile();
        } catch (IOException e2) {
            assertTrue(false);
        }
        assertTrue(lockCrl.exists());
        final CrlHandler crlHandler = new CrlHandler();
        assertTrue(lockDir.setReadable(true,true) && lockDir.setWritable(false,true) && lockDir.setExecutable(true,true));

        try {
            crlHandler.clearCrlStore(crlLockInfo);
            assertTrue(false);
        } catch (TrustHandlerException e1) {
            assertTrue(true);
        }
        assertTrue(lockDir.setReadable(true,false) && lockDir.setWritable(true,false) && lockDir.setExecutable(true,false));
        assertTrue(lockCrl.delete());
        assertTrue(lockDir.delete());
        

    }
    
}
