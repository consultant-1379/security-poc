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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.validator.OtpValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificateManagementServiceBeanTest {

    @InjectMocks
    EntityCertificateManagementServiceBean entityCertificateManagementServiceBean;

    @Mock
    CertificateManagementAuthorizationManager CertificateManagementAuthorization;

    @Mock
    EntityCertificateManager certificateManager;

    @Mock
    Logger logger;

    @Mock
    OtpValidator otpvalidator;

    private static Certificate certificate;
    private static SetUPData setupData;
    String entityName = "Entity";
    String entity = "Entity1";

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
     * Method to test generateCertificate method for Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGenerateCertificate() throws CertificateException, java.security.cert.CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

        final CertificateRequest certificateRequest = new CertificateRequest();
        certificate = setupData.getCertificate("certificates/Entity.crt");
        Mockito.when(certificateManager.generateCertificate(entityName, certificateRequest, RequestType.NEW)).thenReturn(certificate);

        final Certificate generatedCertificate = entityCertificateManagementServiceBean.generateCertificate(entityName, certificateRequest);

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
     * Method to test renew certificate method for Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testRenewCertificate() throws CertificateException, java.security.cert.CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);

        final CertificateRequest certificateRequest = new CertificateRequest();
        certificate = setupData.getCertificate("certificates/Entity.crt");
        Mockito.when(certificateManager.generateCertificate(entityName, certificateRequest, RequestType.RENEW)).thenReturn(certificate);

        final Certificate generatedCertificate = entityCertificateManagementServiceBean.renewCertificate(entityName, certificateRequest);

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
     * Method to test occurrence of CertificateGenerationException when generateCertificate method is called.
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_Exception() throws CertificateException, IOException {

        final CertificateRequest csr = new CertificateRequest();

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

        certificate = setupData.getCertificate("certificates/Entity.crt");
        Mockito.when(certificateManager.generateCertificate(entityName, csr, RequestType.NEW)).thenThrow(new CertificateGenerationException("Exception occured while generating the certificate"));

        entityCertificateManagementServiceBean.generateCertificate(entityName, csr);
    }

    /**
     * Method to test listCertificates for Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testListCertificates() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        certificate = setupData.getCertificate("certificates/Entity.crt");
        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        Mockito.when(certificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenReturn(certificates);

        final List<Certificate> returnedCertificates = entityCertificateManagementServiceBean.listCertificates(entityName, CertificateStatus.ACTIVE);

        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), certificates.size());
    }

    /**
     * Method to test occurrence of CertificateNotFoundException when listCertificates method is called.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testListCertificates_Exception() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);
        Mockito.when(certificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("No Certificate found with ACTIVE status"));

        entityCertificateManagementServiceBean.listCertificates(entityName, CertificateStatus.ACTIVE);
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

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);
        Mockito.when(certificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("No Certificate found with ACTIVE status"));

        returnedCertificates = entityCertificateManagementServiceBean.listCertificates_v1(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), 0);
    }

    /**
     * Test Case for Retrieving Active certificate chain For Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_Active() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        CertificateChain expectedCertChain = setupData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        final List<CertificateChain> expectedCertificateChainList = new ArrayList<CertificateChain>();
        expectedCertificateChainList.add(expectedCertChain);
        Mockito.when(certificateManager.getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(expectedCertificateChainList);

        final CertificateChain actualCertChain = entityCertificateManagementServiceBean.getCertificateChain(entityName);
        assertEquals(expectedCertificateChainList.get(0), actualCertChain);
    }

    /**
     * Test Case for Retrieving InActive certificate chain For Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_InActive() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        CertificateChain expectedCertChain = setupData.getEntityCertificateChain(CertificateStatus.INACTIVE);
        final List<CertificateChain> expectedCertificateChainList = new ArrayList<CertificateChain>();
        expectedCertificateChainList.add(expectedCertChain);
        Mockito.when(certificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE)).thenReturn(
                expectedCertificateChainList);

        final List<CertificateChain> actualCertChain = entityCertificateManagementServiceBean.getCertificateChainList(SetUPData.ENTITY_NAME, CertificateStatus.INACTIVE);
        assertEquals(expectedCertificateChainList.get(0), actualCertChain.get(0));
    }

    /**
     * Test Case for Retrieving Active and InActive certificate chain For Entity.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetCertificateChain_Both_ActiveAndInActive() throws CertificateException, IOException {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        final List<CertificateChain> expectedCertificateChainList = new ArrayList<CertificateChain>();
        CertificateChain activeCertChain = setupData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        expectedCertificateChainList.add(activeCertChain);
        CertificateChain inActiveCertChain = setupData.getEntityCertificateChain(CertificateStatus.INACTIVE);
        expectedCertificateChainList.add(inActiveCertChain);

        CertificateStatus[] certStatus = { CertificateStatus.ACTIVE, CertificateStatus.INACTIVE };
        Mockito.when(certificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certStatus)).thenReturn(expectedCertificateChainList);

        final List<CertificateChain> actualCertChain = entityCertificateManagementServiceBean.getCertificateChainList(SetUPData.ENTITY_NAME, certStatus);
        assertEquals(activeCertChain, actualCertChain.get(0));
        assertEquals(inActiveCertChain, actualCertChain.get(1));
    }

    /**
     * Test Case for checking InvalidEntityException if the given entity is not found in the DB.
     */
    @Test(expected = InvalidEntityException.class)
    public void testGetCertificateChain_InvalidEntity() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        Mockito.when(certificateManager.getCertificateChain(entity, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenThrow(
                new InvalidEntityException(ErrorMessages.ENTITY_NOT_FOUND));
        entityCertificateManagementServiceBean.getCertificateChain(entity);

    }

    /**
     * Test Case for checking InvalidEntityException if the given entity certificate is not active.
     */
    @Test(expected = InvalidEntityException.class)
    public void testGetCertificateChain_ActiveCertificateNotFoundForEntity() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        Mockito.when(certificateManager.getCertificateChain(entity, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenThrow(
                new InvalidEntityException(ErrorMessages.ENTITY_ACTIVE_CERTIFICATE_NOT_FOUND));
        entityCertificateManagementServiceBean.getCertificateChain(entity);

    }

    /**
     * Test case for retrieving list trust CA certificates for a given entity.
     *
     * @throws Exception
     */
    @Test
    public void testGetTrustCertificates_Normal() throws Exception {

        final Certificate certificate = setupData.getCertificate("certificates/Entity.crt");
        final List<Certificate> listOfCertificates = new ArrayList<Certificate>();
        listOfCertificates.add(certificate);
        Mockito.when(certificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(listOfCertificates);

        final List<Certificate> listOfTrustCertificates = entityCertificateManagementServiceBean.getTrustCertificates(entityName);
        assertNotNull(listOfTrustCertificates);
        assertEquals(listOfTrustCertificates.size(), listOfCertificates.size());

    }

    /**
     * Test case for generating certificate without CSR.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCertificatewithoutCSR() throws Exception {

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);
        Mockito.when(certificateManager.generateKeyStore(entityName, password, KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(new KeyStoreInfo());

        final KeyStoreInfo keyStoreInfo = entityCertificateManagementServiceBean.generateCertificate(entityName, password, KeyStoreType.PKCS12);

        assertNotNull(keyStoreInfo);

    }

    /**
     * Test case for generating certificate without CSR.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCertificatewithoutCSR_InvlidPassWord() throws Exception {

        final char[] password = { 'e', 'n', 't', 'i', 't', '9' };

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);
        Mockito.when(certificateManager.generateKeyStore(entityName, password, KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(new KeyStoreInfo());

        final KeyStoreInfo keyStoreInfo = entityCertificateManagementServiceBean.generateCertificate(entityName, password, KeyStoreType.PKCS12);

        assertNotNull(keyStoreInfo);

    }

    /**
     * Test case for rekey certificate method.
     *
     * @throws Exception
     */
    @Test
    public void testReKeyCertificate() throws Exception {

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);
        Mockito.when(certificateManager.generateKeyStore(entityName, password, KeyStoreType.PKCS12, RequestType.REKEY)).thenReturn(new KeyStoreInfo());

        final KeyStoreInfo keyStoreInfo = entityCertificateManagementServiceBean.reKeyCertificate(entityName, password, KeyStoreType.PKCS12);

        assertNotNull(keyStoreInfo);

    }

    /**
     * Test case to checking NoTrustProfileFoundException if there is no trust profile found for given entity.
     *
     * @throws Exception
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetTrustCertificates_WithNoTrustProfile() throws Exception {

        Mockito.when(certificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(
                new ProfileNotFoundException("No trust profile is available for the entity " + entityName));
        entityCertificateManagementServiceBean.getTrustCertificates(entityName);
    }

    /**
     * Test case for checking EntityNotFoundException is thrown when given entity is invalid.
     *
     * @throws Exception
     */

    @Test(expected = EntityNotFoundException.class)
    public void testGetTrustCertificates_EntityNotFound() throws Exception {

        Mockito.when(certificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND));
        entityCertificateManagementServiceBean.getTrustCertificates(entityName);
    }

    /**
     * Test Case for checking InvalidCAEntityException if the given CAEntity has no active certificate.
     *
     * @throws Exception
     */

    @Test(expected = InvalidCAException.class)
    public void testGetTrustCertificates_ActiveCertificateNotFoundForCAEntity() throws Exception {

        Mockito.when(certificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(
                new InvalidCAException(ErrorMessages.CA_ACTIVE_CERTIFICATE_NOT_FOUND));
        entityCertificateManagementServiceBean.getTrustCertificates(entityName);

    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while retrieving the trust profile.
     *
     * @throws Exception
     */

    @Test(expected = CertificateServiceException.class)
    public void testGetTrustCertificates_CertificateServiceException() throws Exception {

        Mockito.when(certificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new CertificateServiceException(ErrorMessages.INTERNAL_ERROR));
        entityCertificateManagementServiceBean.getTrustCertificates(entityName);
    }

    @Test
    public void testPublishCertificate() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);
        entityCertificateManagementServiceBean.publishCertificate(entityName);
    }

    @Test
    public void testUnPublishCertificate() {

        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);
        entityCertificateManagementServiceBean.unPublishCertificate(entityName);
    }

    @Test(expected = InvalidOTPException.class)
    public void testgenerateCertificate() {
        CertificateRequest certificateRequest = null;
        Mockito.doNothing().when(CertificateManagementAuthorization).authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);
        Mockito.when(otpvalidator.isOtpValid("", "")).thenReturn(false);
        entityCertificateManagementServiceBean.generateCertificate("test", certificateRequest, "test");
    }

}
