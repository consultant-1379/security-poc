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

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;



import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CrlHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.*;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
@RunWith(MockitoJUnitRunner.class)
public class CrlManagerTest {

	@Mock
    static CredMService mockRmiClient;

	 String entityProfileName = "p";
	 @InjectMocks
	 CredMServiceWrapper mockWrapper;
	 
	 @Test
    public void testHandlerGetCrlMock() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException {

        final CrlHandler crlHandler = new CrlHandler();
        final CredentialManagerCrlMaps crlMapsTest = PrepareCertificate.generateCrl();
        CredentialManagerCrlMaps crlMap = null;
        
        // testcase: get valid CRL from service
        try {
        	when(mockRmiClient.getCRLs(this.entityProfileName, false)).thenReturn(crlMapsTest);
            crlMap = crlHandler.getTrustCRLs(this.mockWrapper, this.entityProfileName);
        } catch (final Exception e) {
            assertTrue("testHandlerGetCrlMock: exception occurred", false);
            e.printStackTrace();
            return;
        }
        assertTrue("testGetTrust: Internal Crl is null", (crlMap.getInternalCACrlMap() != null));
        assertTrue("testGetTrust: External Crl is null", (crlMap.getExternalCACrlMap() != null));
        assertTrue("testGetTrust: Internal Crl Map NOT contain pippo key", (crlMap.getInternalCACrlMap().containsKey("pippo")) == true);
        assertTrue("testGetTrust: External Crl Map NOT contain pluto key", (crlMap.getExternalCACrlMap().containsKey("pluto")) == true);

        //testcase: get null CRL from service
        boolean exceptionReceived = false;
        try {
            when(mockRmiClient.getCRLs(this.entityProfileName, false)).thenReturn(null);
            crlMap = crlHandler.getTrustCRLs(this.mockWrapper, this.entityProfileName);
        } catch (final TrustHandlerException e) {
            assertTrue("testGetTrust: exception expected (null CRL)", e.getMessage().contains("caMapCrl is NULL"));
            exceptionReceived = true;
        }

        assertTrue("Null CRL: Exception not received", exceptionReceived);
    }

    @Test
    public void testWriteAndDeleteCrl() {

        final CrlManager crlManager = new CrlManager(null);

        /****************************
         * Test for BOTH Store
         ****************************/
        /**
         * CA Map Chain
         */
        final CredentialManagerCrlMaps crlListTest = PrepareCertificate.generateCrl();
        crlManager.setCaCrlMaps(crlListTest);
        assertTrue("testWriteCrl getCaCrlListInt", !crlManager.getCaCrlMaps().getInternalCACrlMap().isEmpty());
        assertTrue("testWriteCrl getCaCrlListExt", !crlManager.getCaCrlMaps().getExternalCACrlMap().isEmpty());

        /**
         * create tsInfoList
         */
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlTest.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        crlInfoList.add(crlInfo);

        // test write
        try {
            crlManager.writeCrlList(crlInfoList);
        } catch (final Exception e) {
            assertTrue("testWriteTrust: write failed", false);
            return;
        }

        final File crlTestFile = new File("/tmp/crlTest.crl");
        assertTrue("testWriteTrust(write): file not written", crlTestFile.exists());

        /*
         * internal map contains 1 Crl; external map contains 1 Crl. Check that CrlTestFile contains two Crls
         */
        int counter = 0;
        try (BufferedReader intBr = new BufferedReader(new FileReader("/tmp/crlTest.crl"))) {
            String tmpLine = null;
            while ((tmpLine = intBr.readLine()) != null) {
                if (tmpLine.contains("--BEGIN")) {
                    counter++;
                }
            }

        } catch (final FileNotFoundException exc) {
            assertTrue("testWriteTrust (on Crl Store reading): /tmp/crlTest.crl file not found", false);
        } catch (final IOException e) {
            assertTrue("testWriteTrust (on Crl Store reading): /tmp/crlTest.crl read line failed", false);
        }
        assertTrue("testWriteTrusts(Both crl store reading): it contains more or less than two entry", counter == 2);

        // test delete
        final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo tsInfo = new TrustStoreInfo("/tmp/tsTest.pem", "", TrustFormat.BASE_64, "", "Ts", TrustSource.BOTH);
        tsInfoList.add(tsInfo);

        crlManager.clearCrlStore(crlInfoList);

        assertTrue("testWriteTrust(delete): file not deleted", !crlTestFile.exists());

        /******************************
         * Test for Internal Store
         ******************************/
        /**
         * create Internal Crl trust Store
         */
        final List<TrustStoreInfo> internalCrlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo internalCrlInfo = new TrustStoreInfo("/tmp/internalCrlTest.crl", "", TrustFormat.BASE_64, "", "Internal", TrustSource.INTERNAL);
        internalCrlInfoList.add(internalCrlInfo);

        /**
         * write on Internal Trust Store
         */
        try {
            crlManager.writeCrlList(internalCrlInfoList);
        } catch (final Exception e) {
            assertTrue("testWriteTrust (on Internal Crl Store): write failed", false);
            return;
        }

        final File internalCrlTestFile = new File("/tmp/internalCrlTest.crl");
        assertTrue("testWriteTrust(internal crl store write): file not written", internalCrlTestFile.exists());

        /*
         * internal map contains 1 Crl; external map contains 1 Crl. Check that internalCrlTestFile contains the only one internal Crl
         */
        int count = 0;
        try (BufferedReader intBr = new BufferedReader(new FileReader("/tmp/internalCrlTest.crl"))) {
            String tmpLine = null;
            while ((tmpLine = intBr.readLine()) != null) {
                if (tmpLine.contains("--BEGIN")) {
                    count++;
                }
            }

        } catch (final FileNotFoundException exc) {
            assertTrue("testWriteTrust (on Internal Crl Store reading): file not found", false);
        } catch (final IOException e) {
            assertTrue("testWriteTrust (on Internal Crl Store reading): read line failed", false);
        }
        assertTrue("testWriteTrusts(internal crl store reading): it contains more or less than one entry", count == 1);

        if (!internalCrlTestFile.delete()) {
            assertTrue("testWriteTrusts(internal crl store deleting): failed to delete internal crl store", false);
        }

        /****************************
         * Test for External Store
         ****************************/
        /**
         * create External Crl trust Store
         */
        final List<TrustStoreInfo> externalCrlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo externalCrlInfo = new TrustStoreInfo("/tmp/externalCrlTest.pem", "", TrustFormat.BASE_64, "", "External", TrustSource.EXTERNAL);
        externalCrlInfoList.add(externalCrlInfo);

        /*
         * create an internal map containing only one CRL
         */
        final CredentialManagerCrlMaps InternalCrlListTest = PrepareCertificate.generateInternalCrl();
        crlManager.setCaCrlMaps(InternalCrlListTest);
        assertTrue("testWriteCrl getCaCrlListInt", !crlManager.getCaCrlMaps().getInternalCACrlMap().isEmpty());
        assertTrue("testWriteCrl getCaCrlListExt", crlManager.getCaCrlMaps().getExternalCACrlMap().isEmpty());

        /**
         * write on External Trust Store (it will be empty)
         */
        try {
            crlManager.writeCrlList(externalCrlInfoList);
        } catch (final Exception e) {
            assertTrue("testWriteTrust (on Internal Crl Store): write failed", false);
            return;
        }

        final File externalCrlTestFile = new File("/tmp/externalCrlTest.pem");
        assertTrue("testWriteTrust(external crl store write): /tmp/externalCrlTest.pem file exist", !externalCrlTestFile.exists());

    }

    @Test
    public void testWriteCrlListMapNull() {

        final CrlManager crlManager = new CrlManager(null);

        /**
         * CA Map Chain set to null
         */
        crlManager.setCaCrlMaps(null);

        /**
         * create tsInfoList
         */
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlTest.crl", "", TrustFormat.BASE_64, "", "Test", TrustSource.BOTH);
        crlInfoList.add(crlInfo);

        // test write
        try {
            crlManager.writeCrlList(crlInfoList);
            assertTrue("testWriteCrlListMapNull: Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("testWriteCrlListMapNull: Exception occurred", true);
        }
    }

    @Test
    public void testWriteCrlListWriteExc() {

        final CrlManager crlManager = new CrlManager(null);

        
        /**
         * CA Map Chain
         */
        final CredentialManagerCrlMaps crlListTest = PrepareCertificate.generateCrl();
        crlManager.setCaCrlMaps(crlListTest);
        assertTrue("testWriteCrl getCaCrlListInt", !crlManager.getCaCrlMaps().getInternalCACrlMap().isEmpty());
        assertTrue("testWriteCrl getCaCrlListExt", !crlManager.getCaCrlMaps().getExternalCACrlMap().isEmpty());

        /**
         * create tsInfoList (trust source set to null)
         */
        final List<TrustStoreInfo> crlInfoList = new ArrayList<TrustStoreInfo>();
        final TrustStoreInfo crlInfo = new TrustStoreInfo("/tmp/crlTest.crl", "", TrustFormat.BASE_64, "", "Test", null);
        crlInfoList.add(crlInfo);

        // test write
        try {
            crlManager.writeCrlList(crlInfoList);
            assertTrue("testWriteCrlListWriteExc: Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("testWriteCrlListWriteExc: Exception occurred", true);
        }
    }

    @Test
    public void testRetrieveCrlListMock() {

        final CrlManager crlManager = new CrlManager(this.mockWrapper);

        try {
            final CredentialManagerCrlMaps maps = new CredentialManagerCrlMaps();
            when(mockRmiClient.getCRLs(Matchers.anyString(), Matchers.anyBoolean())).thenReturn(maps);
            crlManager.retrieveCrlList("entityProfileName");
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", false);
        }

    }

    @Test
    public void testRetrieveCrlListExcMock() {

        final CrlManager crlManager = new CrlManager(this.mockWrapper);

        try {
            when(mockRmiClient.getCRLs(Matchers.anyString(), Matchers.anyBoolean())).thenReturn(null);
            crlManager.retrieveCrlList("entityProfileName");
            assertTrue("Exception not occurred", false);
        } catch (final IssueCertificateException e) {
            assertTrue("Exception not expected", true);
        }

    }

}
