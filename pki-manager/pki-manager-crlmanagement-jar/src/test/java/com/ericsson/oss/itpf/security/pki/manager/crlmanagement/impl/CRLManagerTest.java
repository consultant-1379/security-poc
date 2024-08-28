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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
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
import com.ericsson.oss.itpf.security.pki.common.model.util.CertificateAuthorityUtil;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl.CRLPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.Constants;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.eserviceref.CRLManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLPublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.validator.CertificateStatusValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementCoreLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Test Class for CRLManager.
 */
@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CRLManagerTest {

    @InjectMocks
    CRLManager cRLManager;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    CRLPersistenceHandler cRLPersistenceHandler;

    @Mock
    CRLHelper cRLPersistenceHelper;

    @Mock
    CRLManagementService coreCRLManagementService;

    @Mock
    private CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    CrlGenerationInfo crlGenerationInfo;

    @Mock
    HashMap<CACertificateIdentifier, CRLInfo> caCrlHashInfoMap = null;

    @Mock
    Duration duration;

    @Mock
    CRLUnpublishNotifier cRLUnpublishNotifier;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    CertificateStatusValidator certStatusValidator;

    @Mock
    CertificateAuthorityUtil certAuthorityUtil;

    @Mock
    CRLManagementCoreLocalService crlManagementCoreLocalService;

    @Mock
    private CRLPublishNotifier crlPublishNotifier;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    private CRLManagerEServiceProxy crlManagerEServiceProxy;


    private static CACertificateIdentifier caCertificateIdentifier;
    private static CACertificateIdentifier caCertificateIdentifierInvalid;
    private static CAEntity caEntity;
    private static CertificateAuthority certificateAuthority;
    private static Certificate activeCertificate;
    private static List<CRLInfo> cRLInfoList;
    private static CRLInfo cRlInfo;
    private static final boolean isChainRequired = true;
    private static List<Certificate> inActiveCertificatesList;

    private List<CACertificateIdentifier> caCertificateIdentifierList;
    private static final String overlapPeriod = "PT1H1M30S";

    private static final String caName = "ENM_SubCA";
    private List<String> caEntityNameList;

    private CRLNumber crlNumber;
    private final Integer serialNumber = 1000;
    private List<String> caNames;
    private static List<CRLInfo> cRLInfoListUnpublish;
    private CertificateAuthority certificateAuthorityUnpublish;

    /**
     * Prepares initial Data.
     */

    @Before
    public void setUpData() throws CertificateException, NoSuchProviderException, IOException {

        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList = new ArrayList<CRLInfo>();
        activeCertificate = CRLSetUpData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier(Constants.CA_NAME, Constants.VALID_CERTIFICATE_SERIALNUMBER);
        caCertificateIdentifierInvalid = CRLSetUpData.getCACertificateIdentifier(Constants.CA_NAME, "");
        certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        caEntity = CRLSetUpData.getCaEntity(certificateAuthority);

        caCertificateIdentifierList = CRLSetUpData.getCACertificateIdentifierList();
        caEntityNameList = new ArrayList<String>();
        caEntityNameList.add(caName);

        crlNumber = new CRLNumber();
        crlNumber.setSerialNumber(serialNumber);
        caNames = new ArrayList<String>();
        caNames.add(Constants.CA_NAME);
        cRLInfoListUnpublish = new ArrayList<CRLInfo>();
        cRLInfoListUnpublish.add(cRlInfo);
        certificateAuthorityUnpublish = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        certificateAuthorityUnpublish.setCrlInfo(cRLInfoListUnpublish);

        Mockito.when(crlManagerEServiceProxy.getCoreCRLManagementService()).thenReturn(coreCRLManagementService);

    }

    /**
     * Method to test GetCRLByCACertificate.
     */

    @Test
    public void testGetCRLByCACertificate() {
        Mockito.when(cRLPersistenceHelper.getCRLByCACertificate(caCertificateIdentifier, true, true)).thenReturn(cRlInfo);
        CRLInfo cRLInfoActual = cRLManager.getCRLByCACertificate(caCertificateIdentifier);
        assertCRL(cRLInfoActual);
    }

    /**
     * Method to test GetCRLByCACertificate for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetCRLByCACertificate_CANotFoundException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("CA does not exist in PKI Manager for caCertIdentifier"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for CertificateNotFoundException.
     */

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRLByCACertificate_CertificateNotFoundException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException("Certificate Not found"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for CRLServiceException.
     */

    @Test(expected = CRLServiceException.class)
    public void testGetCRLByCACertificate_CRLServiceException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException("Internal error while generating the CRL for caCertIdentifier"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for ExpiredCertificateException.
     */

    @Test(expected = ExpiredCertificateException.class)
    public void testGetCRLByCACertificate_ExpiredCertificateException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException("Certificate expired for caCertIdentifier"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for RevokedCertificateException.
     */

    @Test(expected = RevokedCertificateException.class)
    public void testGetCRLByCACertificate_CertificateRevokedException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException("Certificate revoked for caCertIdentifier"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for CRLValidationException.
     */

    @Test(expected = InvalidCRLGenerationInfoException.class)
    public void testGetCRLByCACertificate_CRLValidationException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException("CRL validation failed for caCertIdentifier"));
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for CRLValidationException.
     */
    @Test(expected = RevokedCertificateException.class)
    public void testGetCRLByCACertificate_RevokedCertificateException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(new RevokedCertificateException());
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method to test GetCRLByCACertificate for ExpiredCertificateException.
     */
    @Test(expected = ExpiredCertificateException.class)
    public void testGetCRLByCACertificate_ExpiredCertificateExp() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(new ExpiredCertificateException());
        testGetCRLByCACertificateHelper();
    }

    /**
     * Method for the common logic.
     */
    private void testGetCRLByCACertificateHelper() {
        Mockito.when(cRLPersistenceHelper.getCRLByCACertificate(caCertificateIdentifier, true, true)).thenThrow(new CRLNotFoundException("CRL Not found"));
        cRLManager.getCRLByCACertificate(caCertificateIdentifier);
    }

    /**
     * Method to test testGetCRLByCAName.
     */
    @Test
    public void testGetCRLByCAName() {
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList.add(cRlInfo);
        final List<Certificate> certList = new ArrayList<Certificate>();
        certList.add(activeCertificate);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.isCRLExists(cRLInfoList, activeCertificate)).thenReturn(true);
        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.ACTIVE, false);
        assertNotNull(cRLInfoMap);
        assertEquals(cRlInfo, cRLInfoMap.get(caCertificateIdentifier).get(0));
    }

    /**
     * Method to test testGetCRLByCAName for CANotFoundException.
     */
    @Test(expected = CANotFoundException.class)
    public void testGetCRLByCAName_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenThrow(new CANotFoundException("CA Not found"));
        cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.ACTIVE, false);
    }

    /**
     * Method to test CRLNotFoundException with No latest CRL.
     * 
     * @return Exception.
     */

    @Test
    public void testGetCRLbyCAName_Latest_CRLNotFoundException() {

        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.EXPIRED);
        cRLInfoList.add(cRlInfo);
        final List<Certificate> certList = new ArrayList<Certificate>();
        List<CRLInfo> expectedCRLInfoList = null;
        certList.add(activeCertificate);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.isCRLExists(cRLInfoList, activeCertificate)).thenReturn(true);
        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.ACTIVE, isChainRequired);
        assertNotNull(cRLInfoMap);
        assertTrue(cRLInfoMap.containsValue(expectedCRLInfoList));

    }

    /**
     * Method to test testGetCRLByCAName for CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRLByCAName_CertificateNotFoundException() {
        caEntity.getCertificateAuthority().setActiveCertificate(null);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.ACTIVE, false);
    }

    /**
     * Method to test testGetCRLByCAName for CRLServiceException.
     */

    @Test(expected = CRLGenerationException.class)
    public void getLatestCRLList_CRLGenerationException() {
        Certificate certificate = new Certificate();
        List<CRLInfo> caCRLInfoListNew = new ArrayList<CRLInfo>();
        caEntity.getCertificateAuthority().setCrlInfo(caCRLInfoListNew);
        CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier("ENM_RootCA", "12345");

        Mockito.when(cRLPersistenceHelper.isCRLExists(cRLInfoList, certificate)).thenReturn(false);
        Mockito.when(cRLPersistenceHandler.getCAEntity("ENM_RootCA")).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.generateCRL(caCertIdentifier)).thenThrow(new CRLGenerationException("clr generation exception"));

        cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.ACTIVE, false);
    }

    /**
     * Method to test testGetCRLByCAName for ExpiredCertificateException.
     */
    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCRLbyCAName_ValidateCerificateStatus_CertificateStatusExpired() {

        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new ExpiredCertificateException("Expired certificate status is not valid to process this request")).when(certStatusValidator).validate(CertificateStatus.EXPIRED);

        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.EXPIRED, false);
        assertNotNull(cRLInfoMap);
    }

    /**
     * Method to test testGetCRLByCAName for RevokedCertificateException.
     */
    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCRLbyCAName_ValidateCerificateStatus_CertificateStatusRevoked() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new RevokedCertificateException("Revoked certificate status is not valid to process this request")).when(certStatusValidator).validate(CertificateStatus.REVOKED);
        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.REVOKED, false);
        assertNotNull(cRLInfoMap);
    }

    /**
     * Method to test testGetCRLByCAName for ExpiredCertificateException and CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetCRLByCAName_validateCertificateChainFailed() {
        Certificate certificate = new Certificate();
        certificate.setStatus(CertificateStatus.EXPIRED);
        List<Certificate> inAtiveCertificates = new ArrayList<Certificate>();
        inAtiveCertificates.add(certificate);
        caEntity.getCertificateAuthority().setInActiveCertificates(inAtiveCertificates);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new ExpiredCertificateException("Certificate Expired Exception")).when(cRLPersistenceHelper).validateCertificateChain(certificate);

        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = cRLManager.getCRLbyCAName(Constants.CA_NAME, CertificateStatus.EXPIRED, false);
        assertNotNull(cRLInfoMap);
    }

    /**
     * Method to test getAllCRLs.
     */

    @Test
    public void testGetAllCRLs() {
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList.add(cRlInfo);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(cRLInfoList);
        List<CRLInfo> cRLActualList = cRLManager.getAllCRLs(caCertificateIdentifier);
        assertNotNull(cRLActualList);
        assertEquals(cRLInfoList.size(), cRLActualList.size());
        assertEquals(cRLInfoList.get(0), cRLActualList.get(0));
    }

    /**
     * Method to test getAllCRLs.
     */

    @Test
    public void testGetAllCRLs_withInActiveCertificate() {
        certificateAuthority = getCertificateAuthority(CertificateStatus.INACTIVE, true);
        caEntity = CRLSetUpData.getCaEntity(certificateAuthority);
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList.add(cRlInfo);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(cRLInfoList);
        List<CRLInfo> cRLActualList = cRLManager.getAllCRLs(caCertificateIdentifier);
        assertNotNull(cRLActualList);
        assertEquals(cRLInfoList.size(), cRLActualList.size());
        assertEquals(cRLInfoList.get(0), cRLActualList.get(0));
    }

    /**
     * Method to test getAllCRLs Exception
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_withNoMatchingCertificate() {
        certificateAuthority = getCertificateAuthority(CertificateStatus.REVOKED, false);
        caEntity = CRLSetUpData.getCaEntity(certificateAuthority);
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList.add(cRlInfo);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(cRLInfoList);
        cRLManager.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetAllCRLs_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenThrow(new CANotFoundException("CA Not found for the given CA Name"));
        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test getAllCRLs for CRLServiceException.
     */

    @Test(expected = CRLServiceException.class)
    public void testGetAllCRLs_CRLServiceException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException("Error occured while generating the CRL for caCertIdentifier"));
        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test Occurrence of CertificateNotFoundException.
     * 
     * @return Exception.
     */

    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_CertificateNotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException("Certificate not found"));
        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test getAllCRLs for CRLNotFoundException.
     */

    @Test(expected = CRLNotFoundException.class)
    public void testGetAllCRLs_CRLNotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(certificatePersistenceHelper.getCertificate(new CACertificateIdentifier())).thenReturn(new CertificateData());
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(null);
        cRLManager.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CRLGenerationException.
     */

    @Test(expected = CRLGenerationException.class)
    public void testGetAllCRLs_CRLGenerationException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenThrow(new CRLNotFoundException("CRL not found"));
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(new CRLGenerationException("Invalid CRLGenerationInfo to generate CRL"));
        cRLManager.getAllCRLs(caCertificateIdentifier);

    }

    /**
     * Method to test getAllCRLs for CANotFoundException.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetAllCRLs_CertificateAuthorityDoesNotExistException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("CA does not exist"));
        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to test testGetAllCRLs for CRLServiceException.
     */
    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException.class)
    public void testGetAllCRLs_InvalidCAException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(cRLPersistenceHelper.getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), true)).thenReturn(activeCertificate);
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenReturn(cRlInfo);
        try {
            Mockito.when(coreCRLManagementService.getAllCRLs(caCertificateIdentifier)).thenThrow(new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException e) {

            Mockito.verify(logger).error(e.getMessage());
        }

        cRLManager.getAllCRLs(caCertificateIdentifier);
    }

    /**
     * Method to get CertificateAuthority
     * 
     * @return CertificateAuthority
     */
    private CertificateAuthority getCertificateAuthority(CertificateStatus status, boolean isMatchingCertificate) {
        certificateAuthority = new CertificateAuthority();
        inActiveCertificatesList = new ArrayList<Certificate>();
        certificateAuthority.setInActiveCertificates(inActiveCertificatesList);
        certificateAuthority.setName(Constants.CA_NAME);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        if (status.equals(CertificateStatus.INACTIVE)) {
            activeCertificate = CRLSetUpData.getCertificate(Constants.INVALID_CERTIFICATE_SERIALNUMBER);
            certificateAuthority.setActiveCertificate(activeCertificate);
            inActiveCertificatesList.add(getInActiveCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER));
            certificateAuthority.setInActiveCertificates(inActiveCertificatesList);
        }
        if (!isMatchingCertificate) {
            activeCertificate = CRLSetUpData.getCertificate(Constants.INVALID_CERTIFICATE_SERIALNUMBER);
            certificateAuthority.setActiveCertificate(activeCertificate);
            inActiveCertificatesList.add(getInActiveCertificate(Constants.INVALID_CERTIFICATE_SERIALNUMBER));
            certificateAuthority.setInActiveCertificates(inActiveCertificatesList);
        }
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setCrlInfo(cRLInfoList);
        return certificateAuthority;

    }

    /**
     * Method to getInActiveCertificate
     * 
     */
    private Certificate getInActiveCertificate(String serialNumber) {
        final Certificate inActiveCertificate = new Certificate();
        inActiveCertificate.setSerialNumber(serialNumber);
        inActiveCertificate.setStatus(CertificateStatus.INACTIVE);
        return inActiveCertificate;

    }

    /**
     * Method to assert cRLInfo
     * 
     */
    private void assertCRL(final CRLInfo cRLInfoActual) {
        assertNotNull(cRLInfoActual);
        assertEquals(cRlInfo.getId(), cRLInfoActual.getId());
        assertEquals(cRlInfo.getCrlNumber(), cRLInfoActual.getCrlNumber());
        assertEquals(cRlInfo.getStatus(), cRLInfoActual.getStatus());
        assertEquals(cRlInfo.getThisUpdate(), cRLInfoActual.getThisUpdate());
        assertEquals(cRlInfo.getNextUpdate(), cRLInfoActual.getNextUpdate());
    }

    /**
     * Method to test getLatestCRLs method success scenario
     * 
     */
    @Test
    public void testGetLatestCRLs() {
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = CRLSetUpData.getCACertCRLInfoMap();
        Mockito.when(cRLPersistenceHandler.getCACertCRLInfoMap()).thenReturn(caCertCRLInfoMap);
        Mockito.when(cRLPersistenceHandler.getOverlapPeriodForCRL(Mockito.any(CRLInfo.class))).thenReturn(overlapPeriod);
        Mockito.when(coreCRLManagementService.getLatestCRLs(Mockito.anyList())).thenReturn(caCertCRLInfoMap);
        cRLManager.getLatestCRLs();

        Mockito.verify(coreCRLManagementService, times(1)).getLatestCRLs(Mockito.anyList());
    }

    /**
     * Method to test getLatestCRLs method with invalid overlap period for CRLInfo.
     * 
     */
    @Test
    public void testGetLatestCRLs_InvalidDurationFormatException() {
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = CRLSetUpData.getCACertCRLInfoMap();
        Mockito.when(cRLPersistenceHandler.getCACertCRLInfoMap()).thenReturn(caCertCRLInfoMap);
        Mockito.when(cRLPersistenceHandler.getOverlapPeriodForCRL(Mockito.any(CRLInfo.class))).thenReturn("String");
        Mockito.when(coreCRLManagementService.getLatestCRLs(Mockito.anyList())).thenReturn(caCertCRLInfoMap);
        cRLManager.getLatestCRLs();
        Mockito.verify(logger).warn(ErrorMessages.INTERNAL_ERROR, "Failed to convert String to Duration");
        Mockito.verify(coreCRLManagementService, times(1)).getLatestCRLs(Mockito.anyList());
    }

    /**
     * Method to test getLatestCRLs method with any runtime exception while fetching required CA certificate list.
     * 
     */
    @Test
    public void testGetLatestCRLs_GenericException() {
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = CRLSetUpData.getCACertCRLInfoMap();
        Mockito.when(cRLPersistenceHandler.getCACertCRLInfoMap()).thenReturn(caCertCRLInfoMap);
        Mockito.when(cRLPersistenceHandler.getOverlapPeriodForCRL(Mockito.any(CRLInfo.class))).thenThrow(new RuntimeException());
        Mockito.when(coreCRLManagementService.getLatestCRLs(Mockito.anyList())).thenReturn(caCertCRLInfoMap);
        cRLManager.getLatestCRLs();
        Mockito.verify(logger).error(ErrorMessages.INTERNAL_ERROR + "null");
        Mockito.verify(coreCRLManagementService, times(1)).getLatestCRLs(Mockito.anyList());
    }

    /**
     * Method to test getLatestCRLs method with any runtime exception like PersistenceException
     * 
     */
    @Test(expected = CRLServiceException.class)
    public void testGetLatestCRLs_PersistenceException() {
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = CRLSetUpData.getCACertCRLInfoMap();
        Mockito.when(cRLPersistenceHandler.getCACertCRLInfoMap()).thenReturn(caCertCRLInfoMap);
        Mockito.when(cRLPersistenceHandler.getOverlapPeriodForCRL(Mockito.any(CRLInfo.class))).thenReturn(overlapPeriod);
        Mockito.when(coreCRLManagementService.getLatestCRLs(Mockito.anyList())).thenThrow(new PersistenceException());

        cRLManager.getLatestCRLs();
        Mockito.verify(logger).error(ErrorMessages.INTERNAL_ERROR + "null");
    }

    /**
     * Method to test testUpdateCRLStatusToExpired
     * 
     */
    @Test
    public void testUpdateCRLStatusToExpired() {

        Mockito.when(cRLPersistenceHandler.updateCRLStatusToExpired()).thenReturn(caCertificateIdentifierList);
        Mockito.when(cRLPersistenceHelper.getCRLByCACertificate(caCertificateIdentifier, true, true)).thenReturn(cRlInfo);

        cRLManager.updateCRLStatusToExpired();

        Mockito.verify(cRLPersistenceHandler, times(1)).updateCRLStatusToExpired();

        Mockito.verify(cRLUnpublishNotifier).notify(caCertificateIdentifierList, CRLUnpublishType.CRL_EXPIRED);

    }

    /**
     * Method to test testUpdateCRLStatusToExpired
     * 
     */
    @Test
    public void testUnpublishInvalidCRLs() {

        cRLInfoList.add(cRlInfo);

        Mockito.when(cRLPersistenceHandler.getCRLInfoByStatus(CRLStatus.LATEST)).thenReturn(cRLInfoList);

        cRLManager.unpublishInvalidCRLs();

        Mockito.verify(cRLPersistenceHandler, times(1)).getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED);
    }

    /**
     * Method to test occurrence of CRLServiceException.
     * 
     */
    @Test(expected = CRLServiceException.class)
    public void testUnpublishInvalidCRLsExpiredStatus_Exception() {

        cRLInfoList.add(cRlInfo);

        Mockito.when(cRLPersistenceHandler.getCRLInfoByStatus(CRLStatus.EXPIRED, CRLStatus.LATEST)).thenReturn(cRLInfoList);

        Mockito.doThrow(new CRLServiceException("Failed")).when(cRLPersistenceHandler).getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED);

        cRLManager.unpublishInvalidCRLs();
    }

    /**
     * Method to test testUpdateCRLStatusToExpired With Expired Certificate
     * 
     */
    @Test
    public void testUnpublishInvalidCRLsExpiredStatus_WithExpiredCertificate() {

        cRlInfo.getIssuerCertificate().setStatus(CertificateStatus.EXPIRED);

        cRLInfoList.add(cRlInfo);

        Mockito.when(cRLPersistenceHandler.getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED)).thenReturn(cRLInfoList);

        cRLManager.unpublishInvalidCRLs();

        Mockito.verify(cRLPersistenceHandler, times(1)).getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED);
    }

    /**
     * Method to test testUpdateCRLStatusToExpired With Revoked Certificate
     * 
     */
    @Test
    public void testUnpublishInvalidCRLsExpiredStatus_WithRevokedCertificate() {

        cRlInfo.getIssuerCertificate().setStatus(CertificateStatus.REVOKED);

        cRLInfoList.add(cRlInfo);

        Mockito.when(cRLPersistenceHandler.getCRLInfoByStatus(CRLStatus.EXPIRED)).thenReturn(cRLInfoList);

        cRLManager.unpublishInvalidCRLs();

        Mockito.verify(cRLPersistenceHandler, times(1)).getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED);
    }

    /**
     * Method to test GenerateCRL.
     */
    @Test
    public void testGenerateCRL() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenReturn(CRLSetUpData.getCRLInfo(CRLStatus.LATEST));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL));

    }

    /**
     * Method to test occurrence of CANotFoundException.
     */
    @Test
    public void testGenerateCRL_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenThrow(new CANotFoundException());
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CA_ENTITY_NOT_FOUND));
    }

    /**
     * Method to test occurrence of CertificateAuthorityDoesNotExistException.
     */
    @Test
    public void testGenerateCRL_NoCAInCore() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(new CANotFoundException("CA Does not exists in core"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CA_ENTITY_NOT_FOUND));
    }

    /**
     * Method to test occurrence of CertificateNotFoundException from pki-core.
     */
    @Test
    public void testGenerateCRL_NoCertificateInCore() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(new CertificateNotFoundException("Certificate Does not exists in core"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CERTIFICATE_NOT_FOUND));
    }

    /**
     * Method to test occurrence of CertificateNotFoundException.
     */
    @Test
    public void testGenerateCRL_CertificateNotFoundException() {
        CertificateAuthority ca = new CertificateAuthority();
        CAEntity caEntity = CRLSetUpData.getCaEntity(ca);
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CERTIFICATE_NOT_FOUND));
    }

    /**
     * Method to test occurrence of InvalidCRLExtensionsException.
     */
    @Test
    public void testGenerateCRL_InvalidCRLExtensionsException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException("InvalidCRLExtensionsException"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID));
    }

    /**
     * Method to test occurrence of CRLValidationException.
     */
    @Test
    public void testGenerateCRL_CRLValidationException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationException("CRLValidationException"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.CRLGENERATION_INFO_NOT_FOUND));
    }

    /**
     * Method to test occurrence of CRLServiceException.
     */
    @Test
    public void testGenerateCRL_CRLServiceException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenThrow(new CRLServiceException("CRLServiceException"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.GENERATE_CRL_ERROR));
    }

    /**
     * Method to test occurrence of ExpiredCertificateException.
     */
    @Test
    public void testGenerateCRL_ExpiredCertificateException() {

        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException("ExpiredCertificateException"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.NO_VALID_CERTIFICATE_FOUND));
    }

    /**
     * Method to test occurrence of PersistenceException.
     */
    @Test
    public void testGenerateCRL_PersistenceException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(crlManagementCoreLocalService.generateCrl((CACertificateIdentifier) Mockito.anyObject())).thenThrow(new PersistenceException("Persistence Exception occurred"));
        Map<CACertificateIdentifier, CRLGenerationStatus> cRLGenerationStatusMap = cRLManager.generateCRL(caEntityNameList, CertificateStatus.ACTIVE);
        assertEquals(1, cRLGenerationStatusMap.size());
        assertTrue(cRLGenerationStatusMap.containsValue(CRLGenerationStatus.GENERATE_CRL_ERROR));
    }

    /**
     * Method to test occurrence of InvalidCertificateStatusException.
     */
    @Test(expected = InvalidCertificateStatusException.class)
    public void testGenerateCRL_WithCertStatusValidator_ExpiredCertificateException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.doThrow(new ExpiredCertificateException("Expired certificate status is not valid to process this request")).when(certStatusValidator).validate(CertificateStatus.EXPIRED);
        cRLManager.generateCRL(caEntityNameList, CertificateStatus.EXPIRED);
    }

    /**
     * Method to test occurrence of InvalidCertificateStatusException.
     */
    @Test(expected = InvalidCertificateStatusException.class)
    public void testGenerateCRL_WithCertStatusValidator_RevokedCertificateException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.doThrow(new RevokedCertificateException("Revoked certificate status is not valid to process this request")).when(certStatusValidator).validate(CertificateStatus.REVOKED);
        cRLManager.generateCRL(caEntityNameList, CertificateStatus.REVOKED);
    }

    /**
     * Method to test GenerateCRL for CRLNotFoundException.
     */
    @Test
    public void testGenerateCRL_CRLNotFoundException() {
        Mockito.when(crlManagementCoreLocalService.generateCrl(caCertificateIdentifier)).thenReturn(CRLSetUpData.getCRLInfo(CRLStatus.LATEST));
        Mockito.when(cRLPersistenceHelper.getCRLByCACertificate(caCertificateIdentifier, true, false)).thenThrow(new CRLNotFoundException(""));
        cRLManager.generateCRL(caCertificateIdentifier);
        Mockito.verify(cRLPersistenceHelper).getCRLByCACertificate(caCertificateIdentifier, true, false);
    }

    /**
     * Method to test GenerateCRL for PersistenceException.
     */
    @Test
    public void testGenerateCRL_Exception() {
        Mockito.when(crlManagementCoreLocalService.generateCrl(caCertificateIdentifier)).thenReturn(CRLSetUpData.getCRLInfo(CRLStatus.LATEST));
        Mockito.when(cRLPersistenceHelper.getCRLByCACertificate(caCertificateIdentifier, true, false)).thenThrow(new PersistenceException());
        cRLManager.generateCRL(caCertificateIdentifier);
        Mockito.verify(cRLPersistenceHelper).getCRLByCACertificate(caCertificateIdentifier, true, false);
    }

    /**
     * Method to test getAllCRLs with CertificateStatus
     */
    @Test
    public void testGetAllCRLs_withCertStatus() {
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoList.add(cRlInfo);
        Map<CACertificateIdentifier, List<CRLInfo>> expectedCRLInfoMap = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        expectedCRLInfoMap.put(caCertificateIdentifier, cRLInfoList);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(Constants.CA_NAME, CertificateStatus.ACTIVE)).thenReturn(expectedCRLInfoMap);
        Map<CACertificateIdentifier, List<CRLInfo>> actualCRLInfoMap = cRLManager.getAllCRLs(Constants.CA_NAME, CertificateStatus.ACTIVE);
        assertEquals(1, actualCRLInfoMap.size());
        assertEquals(expectedCRLInfoMap, actualCRLInfoMap);
    }

    /**
     * Method to test occurrence of CANotFoundException in getAllCRLs
     */
    @Test(expected = CANotFoundException.class)
    public void testGetAllCRLs_withCertStatus_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caName, CertificateStatus.ACTIVE)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("CA Not found for the given CA Name"));
        cRLManager.getAllCRLs(caName, CertificateStatus.ACTIVE);
    }

    /**
     * Method to test occurrence of CertificateNotFoundException in getAllCRLs
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetAllCRLs_withCertStatus_CertificateNotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caName, CertificateStatus.ACTIVE)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException("Certificate does not exists for the given CA"));
        cRLManager.getAllCRLs(caName, CertificateStatus.ACTIVE);
    }

    /**
     * Method to test occurrence of CRLServiceException in getAllCRLs
     */
    @Test(expected = CRLServiceException.class)
    public void testGetAllCRLs_withCertStatus_CRLServiceException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(caName)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getAllCRLs(caName, CertificateStatus.ACTIVE)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException("CRLServiceException occurred while getting CRLs for given CA Name"));
        cRLManager.getAllCRLs(caName, CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetCRLByCRLNumber() {
        cRLInfoList.add(cRlInfo);
        caEntity.getCertificateAuthority().setCrlInfo(cRLInfoList);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        final CRLInfo actualCRLInfo = cRLManager.getCRLByCRLNumber(Constants.CA_NAME, crlNumber);
        assertNotNull(actualCRLInfo);
        assertEquals(cRlInfo, actualCRLInfo);
    }

    @Test
    public void testGetCrl_MismatchWithCoreByCrlNumber() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getCRL(Constants.CA_NAME, crlNumber)).thenReturn(cRlInfo);
        final CRLInfo actualCRLInfo = cRLManager.getCRLByCRLNumber(Constants.CA_NAME, crlNumber);
        assertNotNull(actualCRLInfo);
        assertEquals(cRlInfo, actualCRLInfo);
    }

    @Test(expected = CANotFoundException.class)
    public void testGetCRL_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getCRL(Constants.CA_NAME, crlNumber)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("CANotFound"));
        cRLManager.getCRLByCRLNumber(Constants.CA_NAME, crlNumber);
    }

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRL_CRLNotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getCRL(Constants.CA_NAME, crlNumber)).thenThrow(new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLNotFoundException("CRLNotFound"));
        cRLManager.getCRLByCRLNumber(Constants.CA_NAME, crlNumber);
    }

    @Test(expected = CRLServiceException.class)
    public void testGetCRL_CRLServiceException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.when(coreCRLManagementService.getCRL(Constants.CA_NAME, crlNumber)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException("CRLServiceException"));
        cRLManager.getCRLByCRLNumber(Constants.CA_NAME, crlNumber);
    }

    /**
     * Method to test publish latest CRLs to the CDPS using list of CANames
     */
    @Test
    public void testPublishCRLToCDPS() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.publishCRLToCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.CRL_INFO_NOT_FOUND));
    }

    /**
     * Method to test publish latest CRLs to the CDPS CANotFoundException
     */
    @Test
    public void testPublishCRLToCDPS_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenThrow(new CANotFoundException());

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.publishCRLToCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.CA_ENTITY_NOT_FOUND));
    }

    /**
     * Method to test publish CRL to CDPS which is sent for publish
     */
    @Test
    public void testPublishCRLToCDPS_PublishCRLMapWithLatestCRL() {
        cRLInfoList.add(cRlInfo);
        caEntity.getCertificateAuthority().setCrlInfo(cRLInfoList);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.publishCRLToCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.SENT_FOR_PUBLISH));
    }

    /**
     * Method to test publish CRL to CDPS CRLServiceException
     */
    @Test(expected = CRLServiceException.class)
    public void testPublishCRLToCDPS_CRLServiceException() {
        cRLInfoList.add(cRlInfo);
        caEntity.getCertificateAuthority().setCrlInfo(cRLInfoList);

        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new CRLServiceException("Failed to update PublishToCDPS of CAEntity")).when(cRLPersistenceHandler).updateCAEnity(caEntity, true);

        cRLManager.publishCRLToCDPS(caNames);
    }

    /**
     * Method to test publish CRL to CDPS RevokedCertificateException
     */
    @Test
    public void testPublishCRLToCDPS_RevokedCertificateException() {
        cRLInfoList.add(cRlInfo);
        caEntity.getCertificateAuthority().setCrlInfo(cRLInfoList);

        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new RevokedCertificateException("Certificate validation is failed")).when(cRLPersistenceHelper).validateCertificateChain(cRlInfo.getIssuerCertificate());

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.publishCRLToCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.VALID_CRL_NOT_FOUND));
    }

    /**
     * Method to test unPublish CRLs of the given CAs
     */
    @Test
    public void testUnpublishCRLFromCDPS() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.unpublishCRLFromCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.CRL_INFO_NOT_FOUND));
    }

    /**
     * Method to test unPublish CRLs of the given CAs CANotFoundException
     */
    @Test
    public void testUnpublishCRLFromCDPS_CANotFoundException() {
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenThrow(new CANotFoundException());

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.unpublishCRLFromCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.CA_ENTITY_NOT_FOUND));
    }

    /**
     * Method to test unPublish CRLs of the given CAs those are sent sent for unpublish
     */
    @Test
    public void testPublishCRLToCDPS_UnpublishCRLFromCDPS() {
        cRLInfoList.add(cRlInfo);
        caEntity.getCertificateAuthority().setCrlInfo(cRLInfoList);
        Mockito.when(cRLPersistenceHandler.getCAEntity(Constants.CA_NAME)).thenReturn(caEntity);

        Map<String, CRLPublishUnpublishStatus> publishCRLMap = cRLManager.unpublishCRLFromCDPS(caNames);
        assertEquals(1, publishCRLMap.size());
        assertTrue(publishCRLMap.containsValue(CRLPublishUnpublishStatus.SENT_FOR_UNPUBLISH));
    }

    @Test
    public void testdeleteDuplicatesAndInsertLatestCRLs() {
        final String endOfDeleteDuplicatesAndInsertLatestCRLs = "End Of deleteDuplicatesAndInsertLatestCRLs method in CRLManager";
        Mockito.when(cRLPersistenceHandler.getRequiredCACertIds()).thenReturn(caCertificateIdentifierList);
        cRLManager.deleteDuplicatesAndInsertLatestCRLs();
        Mockito.verify(logger, times(1)).debug(endOfDeleteDuplicatesAndInsertLatestCRLs);
    }

}
