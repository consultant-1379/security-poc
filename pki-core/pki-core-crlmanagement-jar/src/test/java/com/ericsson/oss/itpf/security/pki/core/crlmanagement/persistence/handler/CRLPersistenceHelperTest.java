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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.persistence.handler;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.EntityManager;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.*;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;

/**
 * Test Class for CRLPersistenceHelper .
 */

@RunWith(MockitoJUnitRunner.class)
public class CRLPersistenceHelperTest {
    @InjectMocks
    private CRLPersistenceHelper crlPersistenceHelper;

    @Mock
    private Logger logger;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private CRLInfoMapper cRLMapper;

    @Mock
    private CertificateAuthorityModelMapper modelMapper;

    @Mock
    CRLInfoMapper cRLInfoMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    private SystemRecorder systemRecorder;

    private static CertificateAuthorityData certificateAuthorityData;
    private static Set<CertificateData> certificateSet;
    private static CertificateData certificateData;
    private static CertificateAuthority certificateAuthority;
    private static Certificate certificate;
    private static CRLInfo cRLInfo;

    private static String cerficateSerialNumber = "1508f262d31";
    private final static String NAME_PATH = "name";

    /**
     * Prepares initial data.
     */

    @Before
    public void setUpData() {

        cRLInfo = CRLSetUpData.getCRLInfo("ACTIVE");
        certificateAuthorityData = CRLSetUpData.getCertificateAuthorityData();
        certificateSet = new HashSet<CertificateData>();
        certificateData = MockData.getCertificateData(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        certificateSet.add(certificateData);
        certificateAuthorityData = MockData.getCertificateAuthorityData(certificateSet);
        certificate = MockData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        certificateAuthority = MockData.getCertificateAuthority(true, certificate, Constants.STATUS_ACTIVE);

    }

    /**
     * Method to test GetCertificateAuthority.
     */

    @Test
    public void testGetCertificateAuthority() throws CertificateException {
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, Constants.CA_NAME, Constants.NAME_PATH)).thenReturn(certificateAuthorityData);
        Mockito.when(modelMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);
        CertificateAuthority actualCertificateAuthority = crlPersistenceHelper.getCertificateAuthority(Constants.CA_NAME);
        assertNotNull(actualCertificateAuthority);
        assertEquals(certificateAuthority.getName(), actualCertificateAuthority.getName());
        assertEquals(certificateAuthority.getStatus(), actualCertificateAuthority.getStatus());
    }

    /**
     * Method to test occurrence of CertificateAuthorityDoesNotExistException when certificateAuthorityData is null.
     */

    @Test
    public void testGetCertificateAuthority_CertificateAuthorityDoesNotExistException() {
        try {
            Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, Constants.CA_NAME, Constants.NAME_PATH)).thenReturn(null);
            crlPersistenceHelper.getCertificateAuthority(Constants.CA_NAME);
            fail("testGetCertificateAuthority_CertificateAuthorityDoesNotExistException testcase should throw CertificateAuthorityDoesNotExistException");
        } catch (CoreEntityNotFoundException certificateAuthorityDoesNotExistException) {
            assertTrue(certificateAuthorityDoesNotExistException.getMessage().contains(ErrorMessages.CERTIFICATE_AUTHORITY_NOT_FOUND));
        }
    }

    /**
     * Method to test occurrence of CRLServiceException.
     */
    @Test
    public void testGetCertificateAuthority_CRLServiceException() throws IOException, CertificateException {
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, Constants.CA_NAME, Constants.NAME_PATH)).thenReturn(certificateAuthorityData);
        Mockito.doThrow(new javax.persistence.EntityNotFoundException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE)).when(modelMapper).toAPIModel((CertificateAuthorityData) Mockito.any());
        try {
            crlPersistenceHelper.getCertificateAuthority(Constants.CA_NAME);
            fail("testGetCertificateAuthority_CRLServiceException testcase should throw CRLServiceException");
        } catch (CRLServiceException cRLServiceException) {
            assertTrue(cRLServiceException.getMessage().contains(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE));
        }
    }

    /**
     * Method to test udpateCRLInfo.
     */
    @Test
    public void testUpdateCRLInfo() {
        certificateAuthority = CRLSetUpData.getCertificateAuthority();
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, certificateAuthority.getName(), NAME_PATH)).thenReturn(CRLSetUpData.getCertificateAuthorityData());
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        crlPersistenceHelper.updateCRLInfo(certificateAuthority, cerficateSerialNumber, cRLInfo);
        Mockito.verify(persistenceManager).getEntityManager();
    }

    /**
     * Method to test GetCertificateAuthority.
     * 
     * @throws CertificateException
     * @throws InvalidCRLGenerationInfoException
     */

    @Test(expected = CertificateException.class)
    public void testGetCertificateAuthorityCertificateException() throws InvalidCRLGenerationInfoException, CertificateException {
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, Constants.CA_NAME, Constants.NAME_PATH)).thenReturn(certificateAuthorityData);
        Mockito.when(modelMapper.toAPIModel(certificateAuthorityData)).thenThrow(CertificateException.class);
        CertificateAuthority actualCertificateAuthority = crlPersistenceHelper.getCertificateAuthority(Constants.CA_NAME);
        assertNotNull(actualCertificateAuthority);
        assertEquals(certificateAuthority.getName(), actualCertificateAuthority.getName());
        assertEquals(certificateAuthority.getStatus(), actualCertificateAuthority.getStatus());
    }

    @Test
    public void updateCRLStatusToExpiredTest() {

        HashMap<String, Object> parameters = new HashMap<String, Object>();

        List<CRLInfoData> cRLDataList = new ArrayList<CRLInfoData>();

        CRLInfoData cRLInfoData = new CRLInfoData();
        cRLInfoData.setCertificateData(certificateData);
        cRLInfoData.setNextUpdate(new Date());
        cRLDataList.add(cRLInfoData);
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters)).thenReturn(cRLDataList);
        Mockito.when(persistenceManager.updateEntity(cRLInfoData)).thenReturn(cRLInfoData);
        crlPersistenceHelper.updateCRLStatusToExpired();
    }

    @Test
    public void updateCRLStatusToInvalidTest() {

        HashMap<String, Object> parameters = new HashMap<String, Object>();

        List<CRLInfoData> cRLDataList = new ArrayList<CRLInfoData>();

        CRLInfoData cRLInfoData = new CRLInfoData();
        cRLInfoData.setCertificateData(certificateData);
        cRLInfoData.setNextUpdate(new Date());
        cRLDataList.add(cRLInfoData);
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters)).thenReturn(cRLDataList);
        Mockito.when(persistenceManager.updateEntity(cRLInfoData)).thenReturn(cRLInfoData);
        crlPersistenceHelper.updateCRLStatusToInvalid();
    }

    @Test
    public void getCertificateAuthority_InvalidCertificateException() {

        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, Constants.CA_NAME, Constants.NAME_PATH)).thenReturn(certificateAuthorityData);
        Mockito.doThrow(new CRLServiceException(ErrorMessages.INTERNAL_ERROR)).when(modelMapper).toAPIModel((CertificateAuthorityData) Mockito.any());
        try {
            crlPersistenceHelper.getCertificateAuthority(Constants.CA_NAME);
            fail("testGetCertificateAuthority_CRLServiceException testcase should throw CRLServiceException");
        } catch (CRLServiceException cRLServiceException) {
            assertTrue(cRLServiceException.getMessage().contains(ErrorMessages.INTERNAL_ERROR));
        }
    }

}
