/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import static org.junit.Assert.*;
import static org.mockito.Mockito.verify;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CRLManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;

/**
 * Test class for CRLManagementServiceBean
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLManagementServiceBeanTest {

    @InjectMocks
    CRLManagementServiceBean crlManagementServiceBean;

    @Mock
    CRLManager crlManager;

    @Mock
    CRLManagementAuthorizationManager cRLManagementAuthorizationManager;

    @Mock
    Logger logger;

    private CRLInfo cRLInfo;
    private List<CRLInfo> cRLList;
    public static String caEntityName;
    public static boolean isChainRequired;
    private CACertificateIdentifier caCertificateIdentifier;
    private Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap;
    private List<String> caEntityNameList;

    /**
     * Prepares initial Data.
     */

    @Before
    public void setUpData() {
        cRLInfo = CRLSetUpData.getCRLInfo();
        cRLList = new ArrayList<CRLInfo>();
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier();
        crlInfoMap = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        caEntityNameList = new ArrayList<String>();
        caEntityNameList.add(caEntityName);
    }

    /**
     * Method to test getAllCRLs.
     */

    @Test
    public void testGetAllCRLs() {
        Mockito.when(crlManager.getAllCRLs(caCertificateIdentifier)).thenReturn(cRLList);
        List<CRLInfo> crlOutputList = crlManagementServiceBean.getAllCRLs(caCertificateIdentifier);
        assertNotNull(crlOutputList);
        assertEquals(crlOutputList, cRLList);

    }

    /**
     * Method to test getAllCRLs for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetAllCRLs_CANotFoundException() {
        Mockito.when(crlManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CANotFoundException("CA Not Found with the given name"));
        crlManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CertificateNotFoundException.
     */

    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_CertificateNotFoundException() {
        Mockito.when(crlManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CertificateNotFoundException("Certificate Not Found with the given serialNumber"));
        crlManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CRLNotFoundException.
     */

    @Test(expected = CRLNotFoundException.class)
    public void testGetAllCRLs_CRLNotFoundException() {
        Mockito.when(crlManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CRLNotFoundException("CRL Not Found for the given Certificate"));
        crlManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CRLServiceException.
     */

    @Test(expected = CRLServiceException.class)
    public void testGetAllCRLs_CRLServiceException() {
        Mockito.when(crlManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CRLServiceException("CRLServiceException occured"));
        crlManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getCRLByCACertificate.
     */

    @Test
    public void testGetCRLByCACertificate() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenReturn(cRLInfo);
        CRLInfo cRLInfoActual = crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
        assertNotNull(cRLInfoActual);
        assertEquals(cRLInfo.getCrlNumber(), cRLInfoActual.getCrlNumber());
        assertEquals(cRLInfo.getStatus(), cRLInfoActual.getStatus());
        assertEquals(cRLInfo.getIssuerCertificate(), cRLInfoActual.getIssuerCertificate());
        assertEquals(cRLInfo.getNextUpdate(), cRLInfoActual.getNextUpdate());
        assertEquals(cRLInfo.getThisUpdate(), cRLInfoActual.getThisUpdate());

    }

    /**
     * Method to test getCRLByCACertificate for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetCRLByCACertificate_CANotFoundException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new CANotFoundException("CA Not Found with the given name"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRLByCACertificate for CertificateNotFoundException.
     */

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRLByCACertificate_CertificateNotFoundException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new CertificateNotFoundException("Certificate Not Found"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRLByCACertificate for CRLNotFoundException.
     */

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRLByCACertificate_CRLNotFoundException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new CRLNotFoundException("CRL Not Found"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRLByCACertificate for CRLServiceException.
     */

    @Test(expected = CRLServiceException.class)
    public void testGetCRLByCACertificate_CRLServiceException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new CRLServiceException("CRLServiceException occured"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRLByCACertificate for ExpiredCertificateException.
     */

    @Test(expected = ExpiredCertificateException.class)
    public void testGetCRLByCACertificate_ExpiredCertificateException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new ExpiredCertificateException("Given Certificate is Expired"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRLByCACertificate for RevokedCertificateException.
     */

    @Test(expected = RevokedCertificateException.class)
    public void testGetCRLByCACertificate_RevokedCertificateException() {
        Mockito.when(crlManager.getCRLByCACertificate(caCertificateIdentifier)).thenThrow(new RevokedCertificateException("Given Certificate is revoked"));
        crlManagementServiceBean.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test getCRL.
     */
    @Test
    public void testGetCRLbyCAName() {
        Mockito.doNothing().when(cRLManagementAuthorizationManager).authorizeGetCRL();
        Mockito.when(crlManager.getCRLbyCAName(caEntityName, CertificateStatus.ACTIVE, isChainRequired)).thenReturn(crlInfoMap);
        Map<CACertificateIdentifier, List<CRLInfo>> crlInfoActualMap = crlManagementServiceBean.getCRL(caEntityName, CertificateStatus.ACTIVE, isChainRequired);
        assertNotNull(crlInfoActualMap);
        assertEquals(crlInfoMap, crlInfoActualMap);
    }

    /**
     * Method to test getCRL for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetCRL_CANotFoundException() {
        Mockito.doNothing().when(cRLManagementAuthorizationManager).authorizeGetCRL();
        Mockito.when(crlManager.getCRLbyCAName(caEntityName, CertificateStatus.ACTIVE, isChainRequired)).thenThrow(new CANotFoundException("CA Not Found with the given name"));
        crlManagementServiceBean.getCRL(caEntityName, CertificateStatus.ACTIVE, isChainRequired);
    }

    /**
     * Method to test getCRL for CertificateNotFoundException.
     */

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRL_CertificateNotFoundException() {
        Mockito.when(crlManager.getCRLbyCAName(caEntityName, CertificateStatus.ACTIVE, isChainRequired)).thenThrow(new CertificateNotFoundException("Certificate Not Found"));
        crlManagementServiceBean.getCRL(caEntityName, CertificateStatus.ACTIVE, isChainRequired);
    }

    /**
     * Method to test getCRL for CertificateNotFoundException.
     */

    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCRL_InvalidCertificateStatusException() {
        Mockito.doNothing().when(cRLManagementAuthorizationManager).authorizeGetCRL();
        Mockito.when(crlManager.getCRLbyCAName(caEntityName, CertificateStatus.EXPIRED, isChainRequired)).thenThrow(new InvalidCertificateStatusException("Certificate Status is not valid to getCRL"));
        crlManagementServiceBean.getCRL(caEntityName, CertificateStatus.EXPIRED, isChainRequired);
    }

    /**
     * Method to test getCRL for CRLServiceException.
     */
    @Test(expected = CRLServiceException.class)
    public void testGetCRL_CRLServiceException() {
        Mockito.doNothing().when(cRLManagementAuthorizationManager).authorizeGetCRL();
        Mockito.when(crlManager.getCRLbyCAName(caEntityName, CertificateStatus.ACTIVE, isChainRequired)).thenThrow(new CRLServiceException("CRLServiceException occured"));
        crlManagementServiceBean.getCRL(caEntityName, CertificateStatus.ACTIVE, isChainRequired);
    }

    @Test
    public void testGenerateCRL() {
        crlManagementServiceBean.generateCRL(caCertificateIdentifier);
        verify(crlManager).generateCRL(caCertificateIdentifier);
    }

    @Test
    public void testGetCRL() {
        assertNull(crlManagementServiceBean.getCRL("test", new CRLNumber()));
    }

    @Test
    public void testPublishCRLToCDPS() {
        assertNotNull(crlManagementServiceBean.publishCRLToCDPS(new LinkedList<String>()));
    }

    @Test
    public void testUnpublishCRLFromCDPS() {
        assertNotNull(crlManagementServiceBean.unpublishCRLFromCDPS(new LinkedList<String>()));
    }

    @Test
    public void testGenerateCRL_listOfCANames() {
        Map<CACertificateIdentifier, CRLGenerationStatus> expectedCRLMap = new HashMap<CACertificateIdentifier, CRLGenerationStatus>();
        expectedCRLMap.put(caCertificateIdentifier, CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL);
        Mockito.when(crlManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE)).thenReturn(expectedCRLMap);
        Map<CACertificateIdentifier, CRLGenerationStatus> actualCRLMap = crlManagementServiceBean.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertNotNull(actualCRLMap);
        assertEquals(expectedCRLMap, actualCRLMap);
    }

    @Test
    public void testGetAllCRLs_CertStatus() {
        cRLList.add(cRLInfo);
        Map<CACertificateIdentifier, List<CRLInfo>> expectedCRLMap = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        expectedCRLMap.put(caCertificateIdentifier, cRLList);
        Mockito.when(crlManager.getAllCRLs(caEntityName, CertificateStatus.ACTIVE)).thenReturn(expectedCRLMap);
        Map<CACertificateIdentifier, List<CRLInfo>> actualCRLMap = crlManagementServiceBean.getAllCRLs(caEntityName, CertificateStatus.ACTIVE);
        assertNotNull(actualCRLMap);
        assertEquals(expectedCRLMap, actualCRLMap);
    }
}
