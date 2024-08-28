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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl;

import static org.junit.Assert.*;

import java.util.*;

import javax.xml.datatype.Duration;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.CrlGenerator;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.CrlGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.persistence.handler.CRLPersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

/**
 * Test class for CRLManager.
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLManagerTest {

    @InjectMocks
    private CRLManager cRLManager;

    @Mock
    private CRLPersistenceHelper cRLPersistenceHelper;

    @Mock
    CRLManager mockCRLManager;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    CrlGenerator crlGenerator;

    @Mock
    CrlGeneratorFactory crlGeneratorFactory;

    @Mock
    Duration overlapPeriod;

    @Mock
    CrlGenerationInfo cRlGenerationInfoMocked;

    @Mock
    CRLInfo crlInfoMOcked;

    @Mock
    private SystemRecorder systemRecorder;

    private static CertificateAuthority activeCertificateAuthority;
    private static CertificateAuthority inActiveCertificateAuthority;
    private static Certificate certificate;
    private static List<CRLInfo> cRLInfoList;
    private static List<CACertificateIdentifier> caCertificateIdentifierList;
    private static HashMap<CACertificateIdentifier, CRLInfo> cRLMap;
    private static CACertificateIdentifier caCertificateIdentifier;
    private static CertificateAuthority certificateAuthority;
    private static final String caEntityName = "ENM_RootCA";
    private static Certificate activeCertificate;
    private static List<Certificate> inActiveCertificates;
    private static List<CrlGenerationInfo> crlGenerationInfo;
    private static CrlGenerationInfo cRlGenerationInfo;
    private CRLInfo crlInfoData;

    private CRLNumber crlNumber;
    private static final Integer serialNumber = 1000;
    private static final long id = 1000;
    private static final long crlId = 1033232325;
    private CRLNumber crlNum;
    private static final Integer serialNum = 10001;

    /**
     * Prepares initial Data.
     */
    @Before
    public void SetUpData() {
        caCertificateIdentifier = MockData.getCACertificateIdentifier(Constants.CA_NAME, Constants.VALID_CERTIFICATE_SERIALNUMBER);

        certificate = MockData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setId(1033232325);

        caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        activeCertificateAuthority = MockData.getCertificateAuthority(true, certificate, Constants.STATUS_ACTIVE);
        inActiveCertificateAuthority = MockData.getCertificateAuthority(true, certificate, Constants.STATUS_INACTIVE);
        activeCertificate = CRLSetUpData.getCertificate();

        certificateAuthority = getCertificateAuthority();
        crlGenerationInfo = new ArrayList<CrlGenerationInfo>();
        cRlGenerationInfo = CRLSetUpData.getCrlGenerationInfo();

        crlInfoData = CRLSetUpData.getCRLInfo("LATEST");
        crlInfoData.setId(id);
        crlInfoData.setNextUpdate(new Date());

        crlNumber = new CRLNumber();
        crlNumber.setSerialNumber(serialNumber);
        crlNum = new CRLNumber();
        crlNum.setSerialNumber(serialNum);

    }

    /**
     * Method to test getAllCRLs with Active certificate.
     */
    @Test
    public void testGetAllCRLs_With_ActiveCertificate() {

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(activeCertificateAuthority);
        MockData.addCRLInfo(activeCertificateAuthority);
        cRLInfoList = cRLManager.getAllCRLs(caCertificateIdentifier);
        assertNotNull(cRLInfoList);
        assertEquals(activeCertificateAuthority.getCrlInfo().size(), cRLInfoList.size());
        assertEquals(activeCertificateAuthority.getCrlInfo().get(0), cRLInfoList.get(0));
    }

    /**
     * Method to test getAllCRLs with InActive certificate.
     */
    @Test
    public void testGetAllCRLs_With_InActiveCertificate() {

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(inActiveCertificateAuthority);
        MockData.addCRLInfo(inActiveCertificateAuthority);
        cRLInfoList = cRLManager.getAllCRLs(caCertificateIdentifier);
        assertNotNull(cRLInfoList);
        assertEquals(inActiveCertificateAuthority.getCrlInfo().size(), cRLInfoList.size());
        assertEquals(inActiveCertificateAuthority.getCrlInfo().get(0), cRLInfoList.get(0));
    }

    /**
     * Method to test Occurrence of CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_CertificateNotFoundException() {
        caCertificateIdentifier = MockData.getCACertificateIdentifier(Constants.CA_NAME, Constants.INVALID_CERTIFICATE_SERIALNUMBER);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(activeCertificateAuthority);
        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test Occurrence of CRLNotFoundException.
     */
    @Test
    public void testGetAllCRLs_CRLNotFoundException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(activeCertificateAuthority);
        List<CRLInfo> crlInfoList = cRLManager.getAllCRLs(caCertificateIdentifier);
        assertNull(crlInfoList);
    }

    /**
     * Method to test whether getLatestCRLs method adds null value in HashMap in case of Exception
     */

    @Test
    public void testGetLatestCRLs_Null() {

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(activeCertificateAuthority);
        caCertificateIdentifierList.add(caCertificateIdentifier);
        cRLMap = (HashMap<CACertificateIdentifier, CRLInfo>) cRLManager.getLatestCRLs(caCertificateIdentifierList);
        assertTrue(cRLMap.containsValue(null));
    }

    /**
     * Method to test getLatestCRLs.
     */
    @Test
    public void testGetLatestCRLs() {

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(activeCertificateAuthority);
        MockData.addCRLInfo(activeCertificateAuthority);
        caCertificateIdentifierList.add(caCertificateIdentifier);
        cRLMap = (HashMap<CACertificateIdentifier, CRLInfo>) cRLManager.getLatestCRLs(caCertificateIdentifierList);
        assertEquals(activeCertificateAuthority.getCrlInfo().get(0), cRLMap.get(caCertificateIdentifier));

    }

    /**
     * Method to test Occurrence of CRLServiceException when CrlGenerationInfo for CertificateAuthority is null.
     * 
     * @return Exception.
     */
    @Test(expected = CRLGenerationException.class)
    public void testGenerateCRL_CRLServiceException() {
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier();
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(getCertificateAuthority());

        cRLManager.generateCRL(caCertificateIdentifier);
    }

    /**
     * Method to test Occurrence of CRLServiceException when Failed to generate CRL
     * 
     * @return Exception.
     */
    @Test(expected = CRLServiceException.class)
    public void testGenerateCRL_CRLServiceException_Failed() {
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier();
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier();
        crlGenerationInfo.add(cRlGenerationInfo);

        certificateAuthority.setCrlGenerationInfo(crlGenerationInfo);

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(certificateAuthority);
        Mockito.when(crlGeneratorFactory.getCrlGenerator(certificateAuthority)).thenReturn(crlGenerator);
        Mockito.when(crlGenerator.generateCRL(certificateAuthority, activeCertificate, cRlGenerationInfo)).thenThrow(new CRLServiceException("Failed to generate CRL"));

        cRLManager.generateCRL(caCertificateIdentifier);
    }

    /**
     * Method to test generateCrl.
     */
    @Test
    public void testGenerateCRL() {
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier();
        crlGenerationInfo.add(cRlGenerationInfo);

        certificateAuthority.setCrlGenerationInfo(crlGenerationInfo);

        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(certificateAuthority);
        Mockito.when(crlGeneratorFactory.getCrlGenerator(certificateAuthority)).thenReturn(crlGenerator);
        Mockito.when(crlGenerator.generateCRL(certificateAuthority, activeCertificate, cRlGenerationInfo)).thenReturn(CRLSetUpData.getCRLInfo("LATEST"));

        final CRLInfo actualCRLInfo = cRLManager.generateCRL(caCertificateIdentifier);
        assertNotNull(actualCRLInfo);
        assertEquals(crlId, actualCRLInfo.getId());
        assertEquals(CRLStatus.LATEST, actualCRLInfo.getStatus());

    }

    /**
     * Method to get CertificateAuthority.
     * 
     * @return CertificateAuthority.
     */
    private CertificateAuthority getCertificateAuthority() {
        certificateAuthority = new CertificateAuthority();
        Certificate certificateInactive = MockData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        certificateInactive.setStatus(CertificateStatus.INACTIVE);
        inActiveCertificates = new ArrayList<Certificate>();
        certificateAuthority.setInActiveCertificates(inActiveCertificates);
        certificateAuthority.setName(caEntityName);
        CRLInfo cRlInfo = CRLSetUpData.getCRLInfo("LATEST");
        List<CRLInfo> crlInfo = new ArrayList<CRLInfo>();
        crlInfo.add(cRlInfo);
        certificateAuthority.setCrlInfo(crlInfo);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.isRootCA();
        certificateAuthority.setCrlGenerationInfo(new LinkedList<CrlGenerationInfo>());
        return certificateAuthority;

    }

    /**
     * Method to test generateCRL.
     * 
     */
    @Test
    public void testGenerateCRLforCA() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenReturn(getCertificateAuthorityData());
        Mockito.when(cRLPersistenceHelper.getCRLWithMaxCRLNumber(certificate.getId())).thenReturn(crlInfoData);
        Mockito.when(cRlGenerationInfoMocked.getOverlapPeriod()).thenReturn(overlapPeriod);
        cRLManager.generateCRL(caEntityName, certificate);
        Mockito.verify(logger).info("End of generateCRL method in CRLManager class");
    }

    /**
     * Method to get CertificateAuthority List.
     * 
     * @return CertificateAuthority LIst.
     */

    private List<CertificateAuthority> getCertificateAuthorityList() {

        List<CertificateAuthority> certificateAuthorityList = new LinkedList<CertificateAuthority>();

        CertificateAuthority certificateAuthority = getCertificateAuthority();
        certificateAuthorityList.add(certificateAuthority);
        return certificateAuthorityList;
    }

    /**
     * Method to get CertificateAuthority.
     * 
     * @return CertificateAuthority.
     */
    private CertificateAuthority getCertificateAuthorityData() {
        certificateAuthority = new CertificateAuthority();

        Certificate inactiveCertificate = MockData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        inactiveCertificate.setStatus(CertificateStatus.ACTIVE);

        inActiveCertificates.add(inactiveCertificate);
        certificateAuthority.setInActiveCertificates(inActiveCertificates);
        certificateAuthority.setName(caEntityName);

        CRLInfo cRlInfo = CRLSetUpData.getCRLInfo("LATEST");
        List<CRLInfo> crlInfo = new ArrayList<CRLInfo>();
        crlInfo.add(cRlInfo);

        certificateAuthority.setCrlInfo(crlInfo);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.isRootCA();

        CrlGenerationInfo crlGenerationInfo = CRLSetUpData.getCrlGenerationInfo();
        LinkedList<CrlGenerationInfo> crlGenerationInfoList = new LinkedList<CrlGenerationInfo>();
        crlGenerationInfoList.add(crlGenerationInfo);

        certificateAuthority.setCrlGenerationInfo(crlGenerationInfoList);
        certificateAuthority.setInActiveCertificates(inActiveCertificates);

        return certificateAuthority;

    }

    /**
     * Method to test Update CRL Status To Expired.
     */
    @Test
    public void testUpdateCRLStatusToExpired() {

        cRLManager.updateCRLStatusToExpired();

    }

    /**
     * Method to test Update CRLStatus To Invalid.
     */
    @Test
    public void testUpdateCRLStatusToInvalid() {

        cRLManager.updateCRLStatusToInvalid();

    }

    /**
     * Method to test occurrence of CRLNotFoundException.
     */
    @Test
    public void testgetAllCRLs_CRLNotFoundException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(activeCertificateAuthority);
        Map<CACertificateIdentifier, List<CRLInfo>> crlsMap = cRLManager.getAllCRLs(caEntityName, CertificateStatus.ACTIVE);
        assertNull(crlsMap.get(0));

    }

    /**
     * Method to test getAllCRLs by taking caEntityName and CertificateStatus with Revoked certificate.
     */
    @Test
    public void testgetAllCRLsWithRevokedCert() {
        mockdata(CertificateStatus.REVOKED);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(inActiveCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.REVOKED);

        Mockito.verify(logger).error(ErrorMessages.CRL_NOT_FOUND + " for the certificate serial number " + certificate.getSerialNumber());

    }

    /**
     * Method to test getAllCRLs by taking caEntityName and CertificateStatus with Inactive certificate.
     */
    @Test
    public void testgetAllCRLsWithInactiveCert() {
        mockdata(CertificateStatus.INACTIVE);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(inActiveCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.INACTIVE);

        Mockito.verify(logger).error(ErrorMessages.CRL_NOT_FOUND + " for the certificate serial number " + certificate.getSerialNumber());

    }

    /**
     * Method to test occurrence of CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testgetAllCRLs_CertificateNotFoundException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(CRLSetUpData.getCertificateAuthorityForX509(crlInfoData));
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.EXPIRED);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_NOT_FOUND + " with the given status");

    }

    /**
     * Method to test CertificateNotFound for the given certificate serial number.
     */
    @Test
    public void testgetAllCRLs_CRLNotFoundForSno() {
        mockdata(CertificateStatus.EXPIRED);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(inActiveCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.EXPIRED);

        Mockito.verify(logger).error(ErrorMessages.CRL_NOT_FOUND + " for the certificate serial number " + certificate.getSerialNumber());

    }

    /**
     * Method to test CertificateNotFound for the CertificateAuthority.
     */
    @Test
    public void testgetAllCRLs_CRLNotFoundForCertAuthority() {
        inActiveCertificateAuthority.getInActiveCertificates().get(0).setStatus(CertificateStatus.EXPIRED);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(inActiveCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.EXPIRED);

        Mockito.verify(logger).error(ErrorMessages.CRL_NOT_FOUND + " for the CertificateAuthority{} " + inActiveCertificateAuthority.getName());

    }

    /**
     * Method to test Inactive certificate not found.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testgetAllCRLs_InactiveCertNotFound() {
        activeCertificateAuthority.setInActiveCertificates(null);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(activeCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.EXPIRED);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_NOT_FOUND + " with the status " + CertificateStatus.EXPIRED);

    }

    /**
     * Method to test active certificate not found.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testgetAllCRLs_activeCertNotFound() {
        activeCertificateAuthority.setActiveCertificate(null);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(activeCertificateAuthority);
        cRLManager.getAllCRLs(caEntityName, CertificateStatus.ACTIVE);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_NOT_FOUND + " with the status " + CertificateStatus.ACTIVE);

    }

    public void mockdata(CertificateStatus Status) {
        inActiveCertificateAuthority.getInActiveCertificates().get(0).setStatus(Status);
        cRLInfoList = new ArrayList<CRLInfo>();
        cRLInfoList.add(crlInfoData);
        inActiveCertificateAuthority.setCrlInfo(cRLInfoList);
    }

    /**
     * Method to test getCRL by caName and CRLNumber.
     */
    @Test
    public void testGetCRL() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(certificateAuthority);
        final CRLInfo expectedCRLInfo = certificateAuthority.getCrlInfo().get(0);
        final CRLInfo actualCRLInfo = cRLManager.getCRL(caEntityName, crlNumber);
        assertNotNull(actualCRLInfo);
        assertEquals(expectedCRLInfo, actualCRLInfo);
    }

    /**
     * Method to test occurrence of CRLNotFoundException in getCRL.
     */
    @Test(expected = CRLNotFoundException.class)
    public void testGetCRL_NoMatchingCRL() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(certificateAuthority);
        cRLManager.getCRL(caEntityName, crlNum);
    }

    /**
     * Method to test occurrence of CertificateAuthorityDoesNotExistException in getCRL.
     */
    @Test(expected = CoreEntityNotFoundException.class)
    public void testGetCRL_CertificateAuthorityDoesNotExistException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenThrow(new CoreEntityNotFoundException("Certificate Authority does not exists"));
        cRLManager.getCRL(caEntityName, crlNumber);
    }

    /**
     * Method to test occurrence of CRLServiceException in getCRL.
     */
    @Test(expected = CRLServiceException.class)
    public void testGetCRL_CRLServiceException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenThrow(new CRLServiceException("CRLServiceException occured"));
        cRLManager.getCRL(caEntityName, crlNumber);
    }

    /**
     * Method to test occurrence of CRLNotFoundException in getCRL.
     */
    @Test(expected = CRLNotFoundException.class)
    public void testGetCRL_CRLNotFoundException() {
        certificateAuthority.setCrlInfo(null);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caEntityName)).thenReturn(certificateAuthority);
        cRLManager.getCRL(caEntityName, crlNumber);
    }

    @Test(expected = InvalidCAException.class)
    public void testGetAllCRLs_InvalidCertificateException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenThrow(new InvalidCertificateException());
        cRLInfoList = cRLManager.getAllCRLs(caCertificateIdentifier);

    }

    @Test(expected = InvalidCAException.class)
    public void testGetAllCRLs_InvalidCRLGenerationInfoException() {
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName())).thenThrow(new InvalidCRLGenerationInfoException(""));
        cRLInfoList = cRLManager.getAllCRLs(caCertificateIdentifier);

    }

    @Test
    public void testGenerateCRLforCACertExpired() {
        final CRLInfo crlInfo = CRLSetUpData.getCRLInfo("EXPIRED");
        crlGenerationInfo.add(cRlGenerationInfo);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        cRlGenerationInfo.setCaCertificates(certificates);
        activeCertificateAuthority.setCrlGenerationInfo(crlGenerationInfo);
        Mockito.when(crlGeneratorFactory.getCrlGenerator(certificateAuthority)).thenReturn(crlGenerator);
        Mockito.when(crlGenerator.generateCRL(certificateAuthority, activeCertificate, cRlGenerationInfo)).thenReturn(crlInfo);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(Mockito.anyString())).thenReturn(activeCertificateAuthority);
        Mockito.when(cRLPersistenceHelper.getCRLWithMaxCRLNumber(Mockito.anyLong())).thenReturn(crlInfo);
        cRLManager.generateCRL(caEntityName, certificate);
        Mockito.verify(logger).info("End of generateCRL method in CRLManager class");
    }

    @Test
    public void testGenerateCRLforCACertLatest() {
        final CRLInfo crlInfo = CRLSetUpData.getCRLInfo("LATEST");
        crlInfo.setNextUpdate(new Date());
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        cRlGenerationInfo.setCaCertificates(certificates);
        activeCertificateAuthority.setCrlGenerationInfo(crlGenerationInfo);
        Mockito.when(crlGeneratorFactory.getCrlGenerator(certificateAuthority)).thenReturn(crlGenerator);
        Mockito.when(crlGenerator.generateCRL(certificateAuthority, activeCertificate, cRlGenerationInfo)).thenReturn(crlInfo);
        Mockito.when(cRLPersistenceHelper.getCertificateAuthority(Mockito.anyString())).thenReturn(activeCertificateAuthority);
        Mockito.when(cRLPersistenceHelper.getCRLWithMaxCRLNumber(Mockito.anyLong())).thenReturn(crlInfo);
        cRLManager.generateCRL(caEntityName, certificate);
        Mockito.verify(logger).info("End of generateCRL method in CRLManager class");
    }

}
