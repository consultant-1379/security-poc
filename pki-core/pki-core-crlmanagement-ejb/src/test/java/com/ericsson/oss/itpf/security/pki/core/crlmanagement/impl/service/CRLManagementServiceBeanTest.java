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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.service;

import static org.junit.Assert.*;

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
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 * Test Class for CRLManagementServiceBean.
 */

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementServiceBeanTest {
    @InjectMocks
    private CRLManagementServiceBean cRLManagementServiceBean;

    @Mock
    private CRLManager cRLManager;

    @Mock
    private Logger logger;

    private static CACertificateIdentifier caCertificateIdentifier;
    private static List<CRLInfo> cRLInfoList;
    private static List<CACertificateIdentifier> caCertificateIdentifierList;
    private static HashMap<CACertificateIdentifier, CRLInfo> latestCRLsMap;
    private static final String CA_NAME = "ENM_RootCA";
    private static final long id = 10;

    private static Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap;

    private static final Integer serialNumber = 10101;
    private static final String caEntityName = "ENM_CAEntity";
    private final CRLNumber crlNumber = new CRLNumber();
    private static CRLInfo expecetdCRLInfo;
    private static final String status = "LATEST";

    /**
     * Prepares initial data.
     */
    @Before
    public void SetUpData() {
        caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(CA_NAME);
        cRLInfoList = new ArrayList<CRLInfo>();
        caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        latestCRLsMap = new HashMap<CACertificateIdentifier, CRLInfo>();
        crlInfoMap = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        crlInfoMap.put(caCertificateIdentifier, cRLInfoList);
        crlNumber.setSerialNumber(serialNumber);
        expecetdCRLInfo = CRLSetUpData.getCRLInfo(status);

    }

    /**
     * Method To Test Getting All CRLs.
     */

    @Test
    public void testGetAllCRLs() {
        Mockito.when(cRLManager.getAllCRLs(caCertificateIdentifier)).thenReturn(cRLInfoList);
        List<CRLInfo> crlExpectedList = cRLManagementServiceBean.getAllCRLs(caCertificateIdentifier);
        assertNotNull(crlExpectedList);
        assertEquals(cRLInfoList.size(), crlExpectedList.size());

    }

    /**
     * Method to test occurrence of CertificateAuthorityDoesNotExistException when getAllCRLs method is called.
     */

    @Test(expected = CoreEntityNotFoundException.class)
    public void testGetAllCRLs_CertificateAuthorityDoesNotExistException() {
        Mockito.when(cRLManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CoreEntityNotFoundException("CertificateAuthorityDoesNotExistException"));
        cRLManagementServiceBean.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test occurrence of CRLServiceException when getAllCRLs method is called.
     */
    @Test(expected = CRLServiceException.class)
    public void testGetAllCRLs_CRLServiceException() {
        Mockito.when(cRLManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CRLServiceException("CRLServiceException"));
        cRLManagementServiceBean.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test occurrence of CertificateNotFoundException when getAllCRLs method is called.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_CertificateNotFoundException() {
        Mockito.when(cRLManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CertificateNotFoundException("CertificateNotFoundException"));
        cRLManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test occurrence of CRLNotFoundException when getAllCRLs method is called.
     */

    @Test(expected = CRLNotFoundException.class)
    public void testGetAllCRLs_CRLNotFoundException() {
        Mockito.when(cRLManager.getAllCRLs(caCertificateIdentifier)).thenThrow(new CRLNotFoundException("CRLNotFoundException"));
        cRLManagementServiceBean.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method To Test getLatestCRLs.
     */

    @Test
    public void testGetLatestCRLs() {

        Mockito.when(cRLManager.getLatestCRLs(caCertificateIdentifierList)).thenReturn(latestCRLsMap);
        Map<CACertificateIdentifier, CRLInfo> latestExpectedCRLsMap = cRLManagementServiceBean.getLatestCRLs(caCertificateIdentifierList);
        assertNotNull(latestExpectedCRLsMap);
        assertEquals(latestCRLsMap.size(), latestExpectedCRLsMap.size());

    }

    /**
     * Method to test occurrence of CRLServiceException when getLatestCRLs method is called.
     */

    @Test(expected = CRLServiceException.class)
    public void testGetLatestCRLs_CRLServiceException() {
        Mockito.when(cRLManager.getLatestCRLs(caCertificateIdentifierList)).thenThrow(new CRLServiceException("CRLServiceException"));
        cRLManagementServiceBean.getLatestCRLs(caCertificateIdentifierList);
    }

    /**
     * Method to test getAllCRLs.
     */
    @Test
    public void testgetAllCRLs() {
        cRLInfoList.add(getCRLInfo());
        Mockito.when(cRLManager.getAllCRLs(CA_NAME, CertificateStatus.ACTIVE)).thenReturn(crlInfoMap);
        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManagementServiceBean.getAllCRLs(CA_NAME, CertificateStatus.ACTIVE);

        assertEquals(cRLInfoMap.get(caCertificateIdentifier).get(0).getId(), id);
        assertEquals(cRLInfoMap.get(caCertificateIdentifier).get(0).getCrlNumber().getSerialNumber(), new Integer(10));

    }

    /**
     * Method to get values to CRLInfo.
     * 
     * @return CRLInfo
     */
    private static CRLInfo getCRLInfo() {
        final CRLInfo crl = new CRLInfo();
        CRLNumber crlNumber = new CRLNumber();
        crlNumber.setSerialNumber(new Integer(10));
        crl.setCrlNumber(crlNumber);
        crl.setId(id);
        crl.setStatus(CRLStatus.LATEST);
        return crl;
    }

    /**
     * Method To Test getCRLs by CAEntityName and CRLNumber.
     */
    @Test
    public void testGetCRL() {
        Mockito.when(cRLManager.getCRL(caEntityName, crlNumber)).thenReturn(expecetdCRLInfo);
        final CRLInfo actualCRLInfo = cRLManagementServiceBean.getCRL(caEntityName, crlNumber);
        assertNotNull(actualCRLInfo);
        assertEquals(expecetdCRLInfo, actualCRLInfo);
    }

    @Test
    public void testGenerateCRL() {
        Mockito.when(cRLManager.generateCRL(caCertificateIdentifier)).thenReturn(expecetdCRLInfo);
        final CRLInfo actualCRLInfo = cRLManagementServiceBean.generateCRL(caCertificateIdentifier);
        assertNotNull(actualCRLInfo);
        assertEquals(expecetdCRLInfo, actualCRLInfo);
    }

    /**
     * Method To Test getCRLs by CAEntityName and CRLNumber.
     */
    @Test(expected = CRLServiceException.class)
    public void testGetCRL_CRLServiceException() {
        Mockito.when(cRLManager.getCRL(caEntityName, crlNumber)).thenThrow(new CRLServiceException("CRLServiceException occured"));
        cRLManagementServiceBean.getCRL(caEntityName, crlNumber);
    }

}
