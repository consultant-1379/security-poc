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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.ExtCAIssuerCertificateChainBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility.CertificateManagementUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.ImportCertificateHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.CAEntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.ImportCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.builders.ValidateItemBuilder;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@RunWith(MockitoJUnitRunner.class)
public class CACertificateManagementServiceBeanTest {

    @InjectMocks
    CACertificateManagementServiceBean cACertificateManagementServiceBean;

    @Mock
    CertificateManagementAuthorizationManager CertificateManagementAuthorization;

    @Mock
    Logger logger;

    @Mock
    CAEntityCertificateManager caEntityCertificateManager;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder;

    @Mock
    ValidationServiceUtils validationServiceUtils;

    @Mock
    ValidationService validationService;

    @Mock
    ImportCertificateManager importCertificateManager;

    @Mock
    Subject subject;

    @Mock
    CACertificateIdentifier caCertificateIdentifier;

    @Mock
    DNBasedCertificateIdentifier dnBasedIdentifier;

    @Mock
    ExtCAIssuerCertificateChainBuilder extCAIssuerCertificateChainBuilder;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    ImportCertificateHandler importCertificateHandler;

    @Mock
    CertificateManagementAuthorizationManager certificateManagementAuthorizationManager;

    @Mock
    CertificateManagementUtility certificateManagementUtility;

    private static Certificate certificate;
    private static SetUPData setupData;
    private final static String entityName = "SubCA";

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setup() {
        setupData = new SetUPData();
    }

    /**
     * Method to test generateCertificate method for CA entity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGenerateCertificate() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.CA_ENTITY);

        certificate = setupData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(caEntityCertificateManager.generateCertificate(entityName)).thenReturn(certificate);

        final Certificate generatedCertificate = cACertificateManagementServiceBean.generateCertificate(entityName);

        assertNotNull(generatedCertificate);
        assertEquals(certificate.getSerialNumber(), generatedCertificate.getSerialNumber());
        assertEquals(certificate.getNotBefore(), generatedCertificate.getNotBefore());
        assertEquals(certificate.getNotAfter(), generatedCertificate.getNotAfter());
        assertEquals(certificate.getStatus(), generatedCertificate.getStatus());
        assertEquals(certificate.getX509Certificate(), generatedCertificate.getX509Certificate());
        assertEquals(certificate.getId(), generatedCertificate.getId());
        assertEquals(certificate.getIssuedTime(), generatedCertificate.getIssuedTime());
    }

    /**
     * Method to test occurrence of EntityNotFoundException when generateCertificate method is called.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGenerateCertificate_InvalidEntityName() {
        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.CA_ENTITY);
        Mockito.when(caEntityCertificateManager.generateCertificate("RootCA")).thenThrow(new EntityNotFoundException(ProfileServiceErrorCodes.NOT_FOUND_WITH_NAME + "RootCA"));
        cACertificateManagementServiceBean.generateCertificate("RootCA");

    }

    /**
     * Method to test occurrence of CertificateGenerationException when generateCertificate method is called.
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_Exception() throws CertificateException, IOException {
        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.CA_ENTITY);
        Mockito.when(caEntityCertificateManager.generateCertificate(entityName)).thenThrow(new CertificateGenerationException("Exception occured while generating the certificate"));

        cACertificateManagementServiceBean.generateCertificate(entityName);

    }

    /**
     * Method to test listCertificates for CA entity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testListCertificates() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        certificate = setupData.getCertificate("certificates/ENMRootCA.crt");
        List<Certificate> certToBeRemoved = new ArrayList<>();
        certToBeRemoved.add(certificate);
        Mockito.when(caEntityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenReturn(certToBeRemoved);
        final List<Certificate> certificates = cACertificateManagementServiceBean.listCertificates(entityName, CertificateStatus.ACTIVE);
        assertEquals(certificates.size(), certificates.size());
    }

    @Test
    public void testListCertificatesExpired() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        certificate = setupData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(caEntityCertificateManager.listCertificates(entityName, CertificateStatus.EXPIRED)).thenReturn(Arrays.asList(certificate));
        final List<Certificate> certificates = cACertificateManagementServiceBean.listCertificates(entityName, CertificateStatus.EXPIRED);
    }

    /**
     * Method to test occurrence of CertificateNotFoundException when listCertificates method is called.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testListCertificates_Exception() throws CertificateException, IOException {
        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);
        Mockito.when(caEntityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("No Certificate found with ACTIVE status"));

        cACertificateManagementServiceBean.listCertificates(entityName, CertificateStatus.ACTIVE);
    }

    /**
     * Method to test whether it returns an empty list if certificates are not found.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testListCertificates_EmptyList() throws CertificateException, IOException {
        List<Certificate> returnedCertificates = null;

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);
        Mockito.when(caEntityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("No Certificate found with ACTIVE status"));

        returnedCertificates = cACertificateManagementServiceBean.listCertificates_v1(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), 0);
    }

    /**
     * Method to test generateCertificate method for CA entity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testRenewCertificate() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        Mockito.doNothing().when(caEntityCertificateManager).renewCertificate(entityName, ReIssueType.CA);

        cACertificateManagementServiceBean.renewCertificate(entityName, ReIssueType.CA);

        Mockito.verify(caEntityCertificateManager).renewCertificate(entityName, ReIssueType.CA);
    }

    @Test
    public void testReKeyCertificate() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        Mockito.doNothing().when(caEntityCertificateManager).renewCertificate(entityName, ReIssueType.CA);

        cACertificateManagementServiceBean.rekeyCertificate(entityName, ReIssueType.CA);

        Mockito.verify(caEntityCertificateManager).rekeyCertificate(entityName, ReIssueType.CA);
    }

    @Test
    public void testreKeyCertificateWithRevocation() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        cACertificateManagementServiceBean.rekeyCertificate(caReIssueInfo, ReIssueType.CA);
    }

    @Test
    public void testexportCSR() {

        final boolean newKey = false;
        Mockito.when(caEntityCertificateManager.generateCSR(entityName, newKey)).thenReturn(pKCS10CertificationRequestHolder);
        assertEquals(pKCS10CertificationRequestHolder, cACertificateManagementServiceBean.generateCSR(entityName, newKey));
    }

    @Test
    public void testimportCertificate() {

        final CAEntity caEntity = new CAEntity();

        final ValidateItem caValidateItem = (new ValidateItemBuilder()).setItem(caEntity).setItemType(ItemType.GENERATE_CSR).setOperationType(OperationType.VALIDATE).build();

        final CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
        caCertificateValidationInfo.setCaName("RootCA");
        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setForceImport(false);

        final ValidateItem validateItem = validationServiceUtils.generateX509CertificateValidateItem(ItemType.X509CERTIFICATE, OperationType.VALIDATE, caCertificateValidationInfo, true);

        Mockito.when(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate)).thenReturn(x509Certificate);
        Mockito.doNothing().when(certificateManagementAuthorizationManager).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        Mockito.when(caEntityCertificateManager.getRootCAEntity("RootCA")).thenReturn(caEntity);
        Mockito.doNothing().when(validationService).validate(caValidateItem);
        Mockito.doNothing().when(validationService).validate(validateItem);
        Mockito.doNothing().when(extCAIssuerCertificateChainBuilder).updateIssuerCertificateChain(x509Certificate);
        Mockito.doNothing().when(extCACertificatePersistanceHandler).validateCertificateChain(x509Certificate);
        Mockito.doNothing().when(importCertificateManager).importCertificate("RootCA", x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);

        cACertificateManagementServiceBean.importCertificate("RootCA", x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);

        Mockito.verify(importCertificateManager).importCertificate("RootCA", x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
        Mockito.verify(extCACertificatePersistanceHandler).validateCertificateChain(x509Certificate);
        Mockito.verify(extCAIssuerCertificateChainBuilder).updateIssuerCertificateChain(x509Certificate);
        Mockito.verify(certificateManagementAuthorizationManager).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
    }

    /**
     * Test Case for Retrieving Active certificate chain For Entity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_Active() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        CertificateChain expectedCertificateChain = setupData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        final List<CertificateChain> CertificateChainList = new ArrayList<CertificateChain>();
        CertificateChainList.add(expectedCertificateChain);
        Mockito.when(caEntityCertificateManager.getCertificateChain(entityName, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(
                CertificateChainList);

        final List<CertificateChain> certificateChains = cACertificateManagementServiceBean.getCertificateChainList(entityName, CertificateStatus.ACTIVE);

        assertNotNull(certificateChains);
        assertEquals(expectedCertificateChain, certificateChains.get(0));
    }

    /**
     * Test Case for Retrieving InActive certificate chain For CAEntity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_InActive() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        CertificateChain expectedInActiveCertificateChain = setupData.getCAEntityCertificateChain(CertificateStatus.INACTIVE);
        final List<CertificateChain> expectedInActiveCertChainList = new ArrayList<CertificateChain>();
        expectedInActiveCertChainList.add(expectedInActiveCertificateChain);
        Mockito.when(caEntityCertificateManager.getCertificateChain(entityName, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(
                expectedInActiveCertChainList);

        final List<CertificateChain> actualCertificateChains = cACertificateManagementServiceBean.getCertificateChainList(entityName, CertificateStatus.ACTIVE);

        assertNotNull(actualCertificateChains);
        assertEquals(expectedInActiveCertificateChain, actualCertificateChains.get(0));
    }

    /**
     * Test Case for Retrieving Active and InActive certificate chains For CAEntity.
     * 
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_ActiveAndInActive() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        final List<CertificateChain> expectedCertChain = new ArrayList<CertificateChain>();
        CertificateChain inActiveCertChain = setupData.getCAEntityCertificateChain(CertificateStatus.INACTIVE);
        expectedCertChain.add(inActiveCertChain);
        CertificateChain activeCertChain = setupData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        expectedCertChain.add(activeCertChain);

        CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE, CertificateStatus.INACTIVE };
        Mockito.when(caEntityCertificateManager.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certificateStatus)).thenReturn(
                expectedCertChain);

        final List<CertificateChain> actualCertificateChains = cACertificateManagementServiceBean.getCertificateChainList(SetUPData.SUB_CA_NAME, certificateStatus);

        assertEquals(expectedCertChain.get(0), actualCertificateChains.get(0));
        assertEquals(expectedCertChain.get(1), actualCertificateChains.get(1));
    }

    /**
     * Test Case for checking InvalidEntityException if the given entity certificate is not active.
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_ActiveCertificateNotFoundForEntity() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        Mockito.when(caEntityCertificateManager.getCertificateChain("SubCA", EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenThrow(
                new InvalidCAException(ErrorMessages.CA_ACTIVE_CERTIFICATE_NOT_FOUND));
        cACertificateManagementServiceBean.getCertificateChainList("SubCA", CertificateStatus.ACTIVE);
    }

    @Test
    public void testRenewCertificates() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        final Set<String> caNames = new HashSet<String>();
        cACertificateManagementServiceBean.renewCertificates(caNames);
    }

    @Test
    public void testRenewCertificateWithRevocation() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
        cACertificateManagementServiceBean.renewCertificate(caReIssueInfo, ReIssueType.CA);
    }

    @Test
    public void testRenewMultipleCertificatesWithRevocation() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        final List<CAReIssueInfo> caReIssueInfoList = new ArrayList<CAReIssueInfo>();
        cACertificateManagementServiceBean.renewCertificates(caReIssueInfoList);
    }

    @Test
    public void testPublishCertificate() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        cACertificateManagementServiceBean.publishCertificate(entityName);
    }

    @Test
    public void testUnPublishCertificate() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        cACertificateManagementServiceBean.unPublishCertificate(entityName);
    }

    @Test
    public void testExportCSRNewKey() {
        Mockito.when(caEntityCertificateManager.generateCSR(entityName, false)).thenReturn(pKCS10CertificationRequestHolder);
        PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = cACertificateManagementServiceBean.generateCSR(entityName, false);

        Assert.assertNotNull(pKCS10CertificationRequestHolder);
        Assert.assertNull(pKCS10CertificationRequestHolder.getCertificateRequest());
    }

    @Test
    public void testExportCSROldKey() {
        Mockito.when(caEntityCertificateManager.generateCSR(entityName, false)).thenReturn(pKCS10CertificationRequestHolder);
        PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = cACertificateManagementServiceBean.generateCSR(entityName, false);

        Assert.assertNotNull(pKCS10CertificationRequestHolder);
        Assert.assertNull(pKCS10CertificationRequestHolder.getCertificateRequest());
    }

    @Test
    public void testGetCSR() {

        CAEntity caentity = setupData.getCAEntity(entityName, subject, true);

        Mockito.when(caEntityCertificateManager.getRootCAEntity(entityName)).thenReturn(caentity);
        Mockito.when(caEntityCertificateManager.getCSR(entityName)).thenReturn(pKCS10CertificationRequestHolder);
        PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = cACertificateManagementServiceBean.getCSR(entityName);
        assertEquals(pkcs10CertificationRequestHolder, cACertificateManagementServiceBean.getCSR(entityName));
    }

    @Test
    public void testgetCertificateChain() {
        CAEntity caentity = setupData.getCAEntity(entityName, subject, true);
        List<Certificate> gCCHolder = cACertificateManagementServiceBean.getCertificateChain(entityName);
        Mockito.when(caEntityCertificateManager.getRootCAEntity(entityName)).thenReturn(caentity);
        Mockito.when(caEntityCertificateManager.getCertificateChain(entityName)).thenReturn(gCCHolder);
        assertEquals(gCCHolder, cACertificateManagementServiceBean.getCertificateChain(entityName));

    }

    @Test
    public void testforceImportCertificate() {
        Mockito.when(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate)).thenReturn(x509Certificate);
        Mockito.doNothing().when(extCAIssuerCertificateChainBuilder).updateIssuerCertificateChain(x509Certificate);
        Mockito.doNothing().when(extCACertificatePersistanceHandler).validateCertificateChain(x509Certificate);

        cACertificateManagementServiceBean.forceImportCertificate("RootCA", x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
        Mockito.verify(importCertificateManager, times(1)).importCertificate("RootCA", x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
    }

    @Test
    public void testlistIssuedCertificate() {
        cACertificateManagementServiceBean.listIssuedCertificates(caCertificateIdentifier, CertificateStatus.ACTIVE);
        Mockito.verify(caEntityCertificateManager, times(1)).listIssuedCertificates(caCertificateIdentifier, CertificateStatus.ACTIVE);
    }

    @Test
    public void testlistIssuedCertificate_DNB() {
        cACertificateManagementServiceBean.listIssuedCertificates(dnBasedIdentifier, CertificateStatus.ACTIVE);
        Mockito.verify(caEntityCertificateManager, times(1)).listIssuedCertificates(dnBasedIdentifier, CertificateStatus.ACTIVE);
    }

}
