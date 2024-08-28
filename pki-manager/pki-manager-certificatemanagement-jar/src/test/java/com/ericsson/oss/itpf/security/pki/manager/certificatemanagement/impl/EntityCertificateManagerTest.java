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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.CertificateManagementBaseTest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateChainHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.AlgorithmCompatibilityValidator;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.KeyStoreUtil;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SdkResourceManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificateManagerTest extends CertificateManagementBaseTest {

    @InjectMocks
    EntityCertificateManager entityCertificateManager;

    @Mock
    AlgorithmCompatibilityValidator algorithmCompatibilityValidator;

    @Mock
    CertificateRequestValidator cSRValidator;

    @Mock
    CertificateGenerationInfoBuilder certificateInfoBuilder;

    @Mock
    CertificateManagementService coreCertificateManagementService;

    @Mock
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    KeyStoreUtil keyStoreUtil;

    @Mock
    Resource resource;

    @Mock
    Logger logger;

    @Mock
    EntityHelper entityHelper;

    @Mock
    CRMFValidator cRMFValidator;

    @Mock
    CertificateValidator certificateValidator;

    @Mock
    CertificateChainHelper certificateChainHelper;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    SdkResourceManagementLocalService sdkResourceManagementLocalService;

    @Mock
    TDPSPersistenceHandler tdpsPersistenceHandler;

    @Mock
    CertificateEventNotifier certificateEventNotifier;
    
    @Mock
	CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    private static SetUPData setUPData;
    private static SubjectSetUPData subjectData;
    private static SubjectAltNameSetUPData subjectAltNameData;
    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUPData;
    private static CertificateGenerationInfoSetUPData certificateGenerationInfoSetUPData;
    private static CertificateRequestMessageSetUPData certificateRequestMessageSetUP;
    private static EntitySetUPData entitySetUPData;

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @Before
    public void setUP() {

        setUPData = new SetUPData();
        subjectData = new SubjectSetUPData();
        subjectAltNameData = new SubjectAltNameSetUPData();
        entitySetUPData = new EntitySetUPData();
        pKCS10CertificationRequestSetUPData = new PKCS10CertificationRequestSetUPData();
        certificateGenerationInfoSetUPData = new CertificateGenerationInfoSetUPData();
        certificateRequestMessageSetUP = new CertificateRequestMessageSetUPData();
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService); 

    }

    /**
     * Test case for generating certificate for an Entity.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate_PKCS10() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");

        final Certificate certificate = mockGenerateCertificate(entity, certificateRequest);

        final Certificate generatedCertificate = entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

        assertCertificate(certificate, generatedCertificate);
    }

    /**
     * Test case for generating certificate for an Entity.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateEcCertificate_PKCS10() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final CertificateRequest certificateRequest = getEcCertificateRequestForPKCS10("CN=RootCA");

        final Certificate certificate = mockGenerateEcCertificate(entity, certificateRequest);

        final Certificate generatedCertificate = entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

        assertCertificate(certificate, generatedCertificate);
    }

    /**
     * Test case for checking EntityNotFoundException is thrown when given entity is invalid.
     * 
     * @throws Exception
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGenerateCertificate_InvalidEntity() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("OU=PKI,O=Ericsson");

        Mockito.when(entityHelper.getEntity("entity")).thenThrow(new EntityNotFoundException(INTERNAL_ERROR));

        entityCertificateManager.generateCertificate("entity", certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CertificateRequest is not passed.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_without_certificateRequest() throws Exception {

        final CertificateRequest certificateRequest = null;
        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when given CertificateRequest does not contain any request holder.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_without_requestHolder() throws Exception {

        final CertificateRequest certificateRequest = new CertificateRequest();
        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for generating certificate when PKCS10CertificationRequestHolder does not contain PKCS#10 request.
     * 
     * @throws Exception
     */
    @Test(expected = NullPointerException.class)
    public void testGenerateCertificate_without_PKCS10CertificationRequest() throws Exception {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = new PKCS10CertificationRequestHolder(null);
        certificateRequest.setCertificateRequestHolder(pKCS10CertificationRequestHolder);
        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when given PKCS10CertificationRequest does not contain Subject and SubjectAltName.
     * 
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws DatatypeConfigurationException
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_PKCS10_without_subjectANDSAN() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, DatatypeConfigurationException {

        final CertificateRequest certificateRequest = getPKCS10withoutSubjectANDSAN();

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
        Mockito.doThrow(new InvalidCertificateRequestException(CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY)).when(cSRValidator).validate(pkcs10CertificationRequestHolder.getCertificateRequest());

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for generating certificate for an entity whose issuerCA does not have ACTIVE certificate.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGenerateCertificate_PKCS10_IssuerCA_Has_NoActiveCertificate() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");
        final Entity entity = entitySetUPData.getEntity();

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);
        Mockito.doThrow(new InvalidCAException("Could not issue certificate because CAEntity " + SetUPData.SUB_CA_NAME + " does not have an ACTIVE certificate")).when(certificateValidator)
                .validateIssuerChain(entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the Entity's key generation algorithm.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_PKCS10_Entity_KeyGenAlgorithm_Not_Matched() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the EntityProfile's key generation algorithm (Entity does not have key
     * generation algorithm).
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_PKCS10_EntityProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");

        final Entity entity = entitySetUPData.getEntity();
        entity.getEntityProfile().setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the CertificateProfile's key generation algorithms
     * (Entity/EntityProfile does not have key generation algorithm).
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_PKCS10_CertificateProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");

        final Entity entity = entitySetUPData.getEntity();
        entity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(Arrays.asList(setUPData.getKeyGenerationAlgorithm("DSA")));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown exception.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_PKCS10_Core_Exception() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException(CERTIFICATE_GENERATION_FAILED));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when PKI Core thrown InvalidCSRException.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_PKCS10_Invalid_CSR() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException(INVALID_CSR));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown InvalidCertificateExtensionsException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_PKCS10_UnsupportedCertificateVersion() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException(INVALID_CERTIFICATE_EXTENSIONS));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking AlgorithmNotFoundException is thrown when PKI Core thrown ValidationException.
     * 
     * @throws Exception
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testGenerateCertificate_PKCS10_Algorithm_Not_Found() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException(ALGORITHM_NOT_FOUND));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateServiceException is thrown when trying to store certificate in database.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_PKCS10_Data_Exception() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doThrow(new PersistenceException("Exception while retrieving certificate")).when(entityPersistenceHelper).storeCertificate(entity, certificateGenerateInfo, certificate);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateEncodingException is thrown when trying to store certificate in database.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificateEncodingException() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setSerialNumber("das");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doThrow(new CertificateEncodingException("Exception while retrieving certificate")).when(entityPersistenceHelper).storeCertificate(entity, certificateGenerateInfo, certificate);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking IOException is thrown when trying to store certificate in database.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificateIOException() throws Exception {

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=Entity");
        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doThrow(new IOException("Exception while retrieving certificate")).when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerateInfo);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for listing Entity certificates
     *
     * @throws Exception
     */
    @Test
    public void testListCertificates_Normal() throws CertificateException, IOException {

        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificates.add(certificate);

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, new CertificateStatus[] { CertificateStatus.ACTIVE })).thenReturn(certificates);

        final List<Certificate> returnedCertificates = entityCertificateManager.listCertificates(SetUPData.ENTITY_NAME, new CertificateStatus[] { CertificateStatus.ACTIVE });

        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), certificates.size());
        assertCertificate(certificate, returnedCertificates.get(0));

    }

    /**
     * Test case for listing Entity certificates
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testListCertificatesCertificateException() throws Exception {

        final List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificates.add(certificate);

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, new CertificateStatus[] { CertificateStatus.ACTIVE })).thenThrow(new CertificateException());

        final List<Certificate> returnedCertificates = entityCertificateManager.listCertificates(SetUPData.ENTITY_NAME, new CertificateStatus[] { CertificateStatus.ACTIVE });

        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), certificates.size());
        assertCertificate(certificate, returnedCertificates.get(0));

    }

    /**
     * Test case for checking CertificateNotFoundException is thrown when Entity does not contain ACTIVE certificate.
     *
     * @throws Exception
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testListCertificates_No_Certificates_Found() throws Exception {

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenReturn(null);

        entityCertificateManager.listCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE);

    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while encoding the certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testListCertificates_IOException() throws Exception {

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, new CertificateStatus[] { CertificateStatus.ACTIVE })).thenThrow(new IOException(ErrorMessages.UNEXPECTED_ERROR));

        entityCertificateManager.listCertificates(SetUPData.ENTITY_NAME, new CertificateStatus[] { CertificateStatus.ACTIVE });
    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while retrieving the certificates from database.
     *
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testListCertificates_DataException() throws Exception {

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE)).thenThrow(new PersistenceException("Exception while retrieving certificate"));

        entityCertificateManager.listCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE);

    }

    /**
     * Test case for retrieving list trust CA certificates for a given entity when chainRequired as true.
     *
     * @throws Exception
     */
    @Test
    public void testGetTrustCertificates_Success() throws Exception {

        final Entity entity = getEntityWithTrustProfiles(true);
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        final List<CertificateChain> certificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(
                certificateChains.get(0).getCertificates());

        final List<Certificate> actualListOfCertificates = entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

        assertEquals(certificateChains.get(0).getCertificates(), actualListOfCertificates);

    }

    /**
     * Test case for retrieving list of trust CA active certificates for a given entity when chainRequired as false.
     * 
     * @throws Exception
     */
    @Test
    public void testGetTrustActiveCertificates_Success() throws Exception {

        final Entity entity = getEntityWithTrustProfiles(true);
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        final List<CertificateChain> certificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenReturn(certificateChains.get(0).getCertificates());

        final List<Certificate> actualListOfCertificates = entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE);

        assertEquals(certificateChains.get(0).getCertificates(), actualListOfCertificates);

    }

    /**
     * Test case for retrieving list trust CA active certificates for a given entity.
     * 
     * @throws Exception
     */

    @Test
    public void testGetTrustActiveCertificates_WithChainRequiredFalse_Success() throws Exception {

        final Entity entity = getEntityWithTrustProfiles(true);
        entity.getEntityProfile().getTrustProfiles().get(0).getTrustCAChains().get(0).setChainRequired(false);
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        final List<CertificateChain> certificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.SUB_CA_NAME, MappingDepth.LEVEL_2, CertificateStatus.ACTIVE)).thenReturn(certificateChains.get(0).getCertificates());

        final List<Certificate> actualListOfCertificates = entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE);

        assertEquals(certificateChains.get(0).getCertificates(), actualListOfCertificates);
    }

    /**
     * Test case to checking ProfileNotFoundException if there is no trust profile available for the given entity.
     *
     * @throws Exception
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testGetTrustCertificates_WithNoTrustProfile() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

    }

    /**
     * Test Case for checking InvalidCAEntityException if the given CAEntity has no active certificate.
     * 
     * @throws Exception
     */

    @Test(expected = InvalidCAException.class)
    public void testGetTrustCertificates_ActiveCertificateNotFoundForCAEntity() throws Exception {

        final Entity entity = getEntityWithTrustProfiles(false);
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(new InvalidCAException());

        entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * Test case for checking CertificateServiceException is thrown if there is any exception while retrieving the trust profile.
     * 
     * @throws Exception
     */

    @Test(expected = CertificateServiceException.class)
    public void testGetTrustCertificates_CertificateServiceException() throws Exception {

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenThrow(new CertificateServiceException(INTERNAL_ERROR));

        entityCertificateManager.getTrustCertificates(SetUPData.ENTITY_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * Test case for generating certificate for an Entity.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate_CRMF() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final X500Name x500Name = new X500Name("CN=RootCA");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Certificate certificate = mockGenerateCertificate(entity, certificateRequest);

        final Certificate generatedCertificate = entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

        assertCertificate(certificate, generatedCertificate);
    }

    /**
     * Test case for generating certificate for an Entity.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateEcCertificate_CRMF() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final X500Name x500Name = new X500Name("CN=RootCA");
        final CertificateRequest certificateRequest = getEcCertificateRequestForCRMF(x500Name);

        final Certificate certificate = mockGenerateEcCertificate(entity, certificateRequest);

        final Certificate generatedCertificate = entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

        assertCertificate(certificate, generatedCertificate);
    }

    /**
     * Test case for generating certificate when given CSR does not contain subject. Here Entity subject values can be taken while generating the certificate.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate_CRMF_Without_Subject() throws Exception {

        final CertificateRequest certificateRequest = createCRMFWithOutSubject();
        final Entity entity = entitySetUPData.getEntity();

        final Certificate certificate = mockGenerateCertificate(entity, certificateRequest);

        final Certificate generatedCertificate = entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

        assertCertificate(certificate, generatedCertificate);

    }

    /**
     * Test case for generating certificate when CSR does not contain CRMF request.
     * 
     * @throws Exception
     */
    @Test(expected = NullPointerException.class)
    public void testGenerateCertificate_CRMF_WithOut_CRMFRequest() throws Exception {

        final CertificateRequest certificateRequest = new CertificateRequest();

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(null);
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCSRException is thrown when given CSR does not contain Subject and SubjectAltName.
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws CertificateException
     * @throws DatatypeConfigurationException
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_CRMF_WithoutSubjectANDSAN() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, OperatorCreationException, IOException,
            CertificateException, DatatypeConfigurationException {

        final CertificateRequest certificateRequest = getCRMFwithoutSubjectANDSAN();

        final Entity entity = entitySetUPData.getEntity();
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
        Mockito.doThrow(new InvalidCertificateRequestException(CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY)).when(cRMFValidator).validate(crmfRequestHolder.getCertificateRequest(), entity);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking EntityNotFoundException is thrown when given entity is invalid.
     * 
     * @throws Exception
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGenerateCertificate_CRMF_InvalidEntity() throws Exception {

        final X500Name x500Name = new X500Name("OU=PKI,O=Ericsson");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenThrow(new EntityNotFoundException(ENTITY_NOT_FOUND));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for generating certificate for an entity whose issuerCA does not have ACTIVE certificate.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGenerateCertificate_CRMF_IssuerCA_Has_NoActiveCertificate() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();
        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.doThrow(new InvalidCAException("Could not issue certificate because CAEntity " + SetUPData.SUB_CA_NAME + " does not have an ACTIVE certificate")).when(certificateValidator)
                .validateIssuerChain(entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the Entity's key generation algorithm.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_CRMF_Entity_KeyGenAlgorithm_Not_Matched() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the EntityProfile's key generation algorithm (Entity does not have key
     * generation algorithm).
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_CRMF_EntityProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();
        entity.getEntityProfile().setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking InvalidCertificateRequestException is thrown when CSR key generation algorithm is not matched with the CertificateProfile's key generation algorithms
     * (Entity/EntityProfile does not have key generation algorithm).
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testGenerateCertificate_CRMF_CertificateProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();
        entity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(Arrays.asList(setUPData.getKeyGenerationAlgorithm("DSA")));

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenThrow(new InvalidCertificateRequestException(INVALID_KEY_GENERATION_ALGORTITHM));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown exception.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_CRMF_Core_Exception() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException(CERTIFICATE_GENERATION_FAILED));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown exception.
     * 
     * @throws Exception
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGenerateCertificateEntityNotFoundException() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException(ENTITY_NOT_FOUND));

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateServiceException is thrown when trying to store certificate in database.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_CRMF_Data_Exception() throws Exception {

        final X500Name x500Name = new X500Name("CN=Entity");
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(x500Name);

        final Entity entity = entitySetUPData.getEntity();

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doThrow(new PersistenceException("Exception while retrieving certificate")).when(entityPersistenceHelper).storeCertificate(entity, certificateGenerateInfo, certificate);

        entityCertificateManager.generateCertificate(SetUPData.ENTITY_NAME, certificateRequest, RequestType.NEW);

    }

    /**
     * Test case for generateCertificate with out CSR
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateCertificateWithoutCSR() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        final KeyStoreInfo expectedKeyStoreInfo = mockKeyStore(password);

        final KeyStoreInfo actualKeyStoreInfo = entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

        assertEquals(expectedKeyStoreInfo, actualKeyStoreInfo);

    }

    /**
     * Method to test occurrence of CertificateGenerationException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificatewithoutCSR_CertificateException_CertificateGenerationException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new PersistenceException()).when(certificateValidator).validateIssuerChain(Mockito.anyString());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateRequestGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CertificateRequestGenerationException_CertificateServiceException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new CertificateRequestGenerationException()).when(entityHelper).generatePKCS10Request((Entity) Mockito.anyObject(), (KeyPair) Mockito.anyObject());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CertificateRequestGenerationException_CertificateServiceException1() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException("FailedCase")).when(coreCertificateManagementService)
                .createCertificate((CertificateGenerationInfo) Mockito.anyObject());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws Exception
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGenerateCertificatewithoutCSREntityNotFoundException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("FailedCase")).when(coreCertificateManagementService)
                .createCertificate((CertificateGenerationInfo) Mockito.anyObject());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CertificateRequestGenerationException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException("FailedCase")).when(coreCertificateManagementService)
                .createCertificate((CertificateGenerationInfo) Mockito.anyObject());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of AlgorithmNotFoundException.
     * 
     * @throws Exception
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testGenerateCertificatewithoutCSR_CertificateRequestGenerationException_AlgorithmNotFoundException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockGenerateCertificatewithoutCSR(entity);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException("FailedCase")).when(coreCertificateManagementService)
                .createCertificate((CertificateGenerationInfo) Mockito.anyObject());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of InvalidEntityException.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGenerateCertificatewithoutCSR_InvalidEntityException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);
        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenReturn(keyPair);

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");
        Mockito.when(entityHelper.generatePKCS10Request(entity, keyPair)).thenReturn(certificateRequest);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(true);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of InvalidEntityException with INVALID_ENTITY_SAN.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGenerateCertificatewithoutCSR_InvalidEntityException_INVALID_ENTITY_SAN() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);
        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenReturn(keyPair);

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");
        Mockito.when(entityHelper.generatePKCS10Request(entity, keyPair)).thenReturn(certificateRequest);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(true);

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of AlgorithmNotFoundException.
     * 
     * @throws Exception
     * @throw AlgorithmNotFoundException
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testGenerateCertificatewithoutCSR_AlgorithmNotFoundException() throws Exception {

        mockGenerateCertificatewithoutCSRForException();

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.when(coreCertificateManagementService.createCertificate((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(new AlgorithmNotFoundException());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateGenerationException.
     * 
     * @throws Exception
     * @throw CertificateGenerationException
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CertificateGenerationException() throws Exception {

        mockGenerateCertificatewithoutCSRForException();

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        Mockito.when(coreCertificateManagementService.createCertificate((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(new CertificateGenerationException());

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test occurrence of CertificateGenerationException.
     * 
     * @throws Exception
     * @throw CertificateGenerationException
     */
    @Test(expected = CertificateRequestGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CertificateGenerationException_FromCertificateRequestGenerationException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenThrow(new CertificateRequestGenerationException());

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };
        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Method to test generateKeyStore when keyStore as null.
     * 
     * @return CertificateGenerationException.
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateKeyStore_With_keystoreAsNull() throws Exception {

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, null, RequestType.NEW);

    }

    /**
     * Test case for generateCertificate with out CSR
     * 
     * @throws Exception
     */
    @Test(expected = CertificateRequestGenerationException.class)
    public void testGenerateCertificatewithoutCSR_CSR_GENERATION_FAILED() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);
        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenReturn(keyPair);

        Mockito.when(entityHelper.generatePKCS10Request(entity, keyPair)).thenThrow(new CertificateRequestGenerationException(CSR_GENERATION_FAILED));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);
    }

    /**
     * Test case for checking InvalidEntityException when subject contains override operator.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGenerateCertificatewithoutCSR_Subject_Contains_OP() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final Subject subject = subjectData.getSubject("?");
        entity.getEntityInfo().setSubject(subject);

        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenThrow(new InvalidEntityException(ErrorMessages.INVALID_ENTITY_SUBJECT));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Test case for checking InvalidEntityException when SAN contains override operator.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGenerateCertificatewithoutCSR_SAN_Contains_OP() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?");
        entity.getEntityInfo().setSubjectAltName(subjectAltName);
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenThrow(new InvalidEntityException(ErrorMessages.INVALID_ENTITY_SUBJECT));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown exception.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificatewithoutCSR_Core_Exception() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(false);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertificateGenerationInfo(entity);
        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException(CERTIFICATE_GENERATION_FAILED));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Test case for checking CertificateGenerationException is thrown when PKI Core thrown InvalidCertificateExtensionsException.
     * 
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificatewithoutCSR_UnsupportedCertificateVersion() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(false);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertificateGenerationInfo(entity);
        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException(INVALID_CERTIFICATE_EXTENSIONS));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    /**
     * Test case for checking AlgorithmNotFoundException is thrown when PKI Core thrown ValidationException.
     * 
     * @throws Exception
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testGenerateCertificatewithoutCSR_Algorithm_Not_Found() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(false);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertificateGenerationInfo(entity);
        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);

        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException(ALGORITHM_NOT_FOUND));

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        entityCertificateManager.generateKeyStore(SetUPData.ENTITY_NAME, password, KeyStoreType.PKCS12, RequestType.NEW);

    }

    @Test
    public void testGetCertificateChain_Active() throws Exception {

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(
                expectedCertificateChains);

        final List<CertificateChain> actualCertificateChains = entityCertificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.ACTIVE);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testGetCertificateChain_InActive() throws Exception {

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.INACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE)).thenReturn(
                expectedCertificateChains);

        final List<CertificateChain> actualCertificateChains = entityCertificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.INACTIVE);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testGetCertificateChain_Both_ActiveAndInActive() throws Exception {

        final CertificateStatus[] certStatus = { CertificateStatus.ACTIVE, CertificateStatus.INACTIVE };

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        expectedCertificateChains.addAll(setUPData.getEntityCertificateChain(CertificateStatus.INACTIVE));

        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certStatus)).thenReturn(
                expectedCertificateChains);

        final List<CertificateChain> actualCertificateChains = entityCertificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                certStatus);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test
    public void testGetCertificateChain_MultipleActiveStatus() throws Exception {

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        Mockito.when(certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(
                expectedCertificateChains);

        final CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE, CertificateStatus.ACTIVE };
        final List<CertificateChain> actualCertificateChains = entityCertificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                certificateStatus);
        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test(expected = InvalidCertificateStatusException.class)
    public void testGetCertificateChain_RevokedStatus() throws Exception {

        final CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE, CertificateStatus.ACTIVE, CertificateStatus.REVOKED };
        entityCertificateManager.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certificateStatus);

    }

    private KeyStoreInfo mockKeyStore(final char[] password) {

        Mockito.when(
                keyStoreUtil.createKeyStore(new char[] { Mockito.anyChar() }, Mockito.any(KeyStoreType.class), Mockito.any(KeyPair.class), Mockito.any(X509Certificate[].class), Mockito.anyString()))
                .thenReturn("mykeystore.jks");

        final byte[] keyStoreFileData = "entity".getBytes();

        final KeyStoreInfo expectedKeyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, password, keyStoreFileData);
        Mockito.when(keyStoreUtil.buildKeyStoreInfoModel(new char[] { Mockito.anyChar() }, Mockito.anyString(), new byte[] { Mockito.anyByte() })).thenReturn(expectedKeyStoreInfo);

        return expectedKeyStoreInfo;
    }

    private Certificate mockGenerateCertificatewithoutCSR(final Entity entity) throws Exception {

        mockCertificateRequest(entity);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(false);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertificateGenerationInfo(entity);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);

        final Certificate certificate = mockCertificate(entity, certificateGenerationInfo);

        return certificate;
    }

    private void mockGenerateCertificatewithoutCSRForException() throws Exception {

        final Entity entity = entitySetUPData.getEntity();
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);
        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenReturn(keyPair);

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");
        Mockito.when(entityHelper.generatePKCS10Request(entity, keyPair)).thenReturn(certificateRequest);

        Mockito.when(entityHelper.isSubjectContainsOverrideOperator(entity)).thenReturn(false);

        Mockito.when(entityHelper.isSANContainsOverrideOperator(entity)).thenReturn(false);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertificateGenerationInfo(entity);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);

    }

    private void mockCertificateRequest(final Entity entity) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(entity)).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);
        Mockito.when(entityHelper.generateKeyPair(setUPData.getKeyGenerationAlgorithm("RSA"))).thenReturn(keyPair);

        final CertificateRequest certificateRequest = getCertificateRequestForPKCS10("CN=RootCA");
        Mockito.when(entityHelper.generatePKCS10Request(entity, keyPair)).thenReturn(certificateRequest);
    }

    private CertificateRequest getCertificateRequestForPKCS10(final String name) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final CertificateRequest certificateRequest = new CertificateRequest();

        final X500Name x500Name = new X500Name(name);
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUPData.generatePKCS10Request(x500Name, "dir2");
        final PKCS10CertificationRequestHolder PKCS10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);

        certificateRequest.setCertificateRequestHolder(PKCS10CertificationRequestHolder);
        return certificateRequest;

    }

    private CertificateRequest getEcCertificateRequestForPKCS10(final String name) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final CertificateRequest certificateRequest = new CertificateRequest();

        final X500Name x500Name = new X500Name(name);
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUPData.generateEcPKCS10Request(x500Name, "dir2");
        final PKCS10CertificationRequestHolder PKCS10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);

        certificateRequest.setCertificateRequestHolder(PKCS10CertificationRequestHolder);
        return certificateRequest;

    }

    private CertificateRequest getPKCS10withoutSubjectANDSAN() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUPData.generatePKCS10Request(x500Name, null);
        final PKCS10CertificationRequestHolder PKCS10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(PKCS10CertificationRequestHolder);
        return certificateRequest;
    }

    private CertificateRequest getCertificateRequestForCRMF(final X500Name x500Name) throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(x500Name, "dir1");
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);
        return certificateRequest;
    }

    private CertificateRequest getEcCertificateRequestForCRMF(final X500Name x500Name) throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateEcCRMFRequest(x500Name, "dir1");
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);
        return certificateRequest;
    }

    private CertificateRequest getCRMFwithoutSubjectANDSAN() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, OperatorCreationException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(x500Name, null);
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);
        return certificateRequest;
    }

    private CertificateRequest createCRMFWithOutSubject() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();
        final CertificateRequest certificateRequest = getCertificateRequestForCRMF(name);
        return certificateRequest;
    }

    private Certificate mockGenerateCertificate(final Entity entity, final CertificateRequest certificateRequest) throws Exception {

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "RSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("RSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockCertificateGenerationInfo(entity);

        final Certificate certificate = mockCertificate(entity, certificateGenerateInfo);

        return certificate;
    }

    private Certificate mockGenerateEcCertificate(final Entity entity, final CertificateRequest certificateRequest) throws Exception {

        mockValidateCertificateRequest(entity, certificateRequest);

        Mockito.when(entityHelper.validateAndGetAlgorithmModel(entity, "ECDSA")).thenReturn(setUPData.getKeyGenerationAlgorithm("ECDSA"));

        final CertificateGenerationInfo certificateGenerateInfo = mockEcCertificateGenerationInfo(entity);

        final Certificate certificate = mockEcCertificate(entity, certificateGenerateInfo);

        return certificate;
    }

    private void mockValidateCertificateRequest(final Entity entity, final CertificateRequest certificateRequest) throws CertificateException, IOException {

        Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);

        if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
            final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
            Mockito.doCallRealMethod().when(cSRValidator).validate(pkcs10CertificationRequestHolder.getCertificateRequest());
        } else {
            final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
            Mockito.doCallRealMethod().when(cRMFValidator).validate(crmfRequestHolder.getCertificateRequest(), entity);
        }

        Mockito.doNothing().when(certificateValidator).validateIssuerChain(entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());
        Mockito.doNothing().when(entityHelper).setEntitySubject(certificateRequest, entity);
        Mockito.doNothing().when(entityHelper).setEntitySubjectAltName(certificateRequest, entity);

    }

    private Certificate mockCertificate(final Entity entity, final CertificateGenerationInfo certificateGenerateInfo) throws CertificateException, IOException {

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificate(entity, certificateGenerateInfo, certificate);

        return certificate;
    }

    private Certificate mockEcCertificate(final Entity entity, final CertificateGenerationInfo certificateGenerateInfo) throws CertificateException, IOException {

        final Certificate certificate = setUPData.getCertificate("certificates/Entity_ECDSA.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.createCertificate(certificateGenerateInfo)).thenReturn(certificate);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificate(entity, certificateGenerateInfo, certificate);

        return certificate;
    }

    private CertificateGenerationInfo mockCertificateGenerationInfo(final Entity entity) throws Exception {

        final CertificateGenerationInfo certificateGenerateInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_Entity();
        Mockito.when(certificateInfoBuilder.build(entity, RequestType.NEW)).thenReturn(certificateGenerateInfo);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerateInfo);

        return certificateGenerateInfo;
    }

    private CertificateGenerationInfo mockEcCertificateGenerationInfo(final Entity entity) throws Exception {

        final CertificateGenerationInfo certificateGenerateInfo = certificateGenerationInfoSetUPData.getEcCertificateGenerationInfo_Entity();
        Mockito.when(certificateInfoBuilder.build(entity, RequestType.NEW)).thenReturn(certificateGenerateInfo);

        Mockito.doNothing().when(entityPersistenceHelper).storeCertificateGenerateInfo(certificateGenerateInfo);

        return certificateGenerateInfo;
    }

    private Entity getEntityWithTrustProfiles(final boolean isCertificateActive) throws CertificateException, DatatypeConfigurationException, IOException {

        final Entity entity = entitySetUPData.getEntity();

        final Certificate certificate = setUPData.getCertificate("certificates/Entity.crt");
        certificate.setStatus(CertificateStatus.ACTIVE);

        final TrustProfile trustProfile = getTrustProfile(certificate, isCertificateActive);
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(trustProfile);

        entity.getEntityProfile().setTrustProfiles(trustProfiles);
        return entity;
    }

    private TrustProfile getTrustProfile(final Certificate certificate, final boolean isCertificateActive) throws DatatypeConfigurationException, CertificateException, IOException {

        final CAEntity caEntity = entitySetUPData.getCAEntity();
        if (isCertificateActive) {
            caEntity.getCertificateAuthority().setActiveCertificate(certificate);
        }
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("Certificate");
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        final TrustCAChain trustCAChain = new TrustCAChain();
        trustCAChain.setChainRequired(true);
        trustCAChain.setInternalCA(caEntity);
        trustCAChains.add(trustCAChain);
        trustProfile.setTrustCAChains(trustCAChains);

        return trustProfile;
    }

    private KeyStoreInfo buildKeyStoreInfoModel(final String alias, final char[] password, final byte[] keyStoreContent) {

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setPassword(password);
        keyStoreInfo.setAlias(alias);
        keyStoreInfo.setKeyStoreFileData(keyStoreContent);

        return keyStoreInfo;
    }

    @Test
    public void testPublishCertificate() throws IOException, CertificateException {
        List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        entityCertificateManager.publishCertificate(SetUPData.ENTITY_NAME);
    }

    @Test(expected = CertificateServiceException.class)
    public void testPublishCertificate_certificateServiceException() throws IOException, CertificateException {

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        entityCertificateManager.publishCertificate(SetUPData.ENTITY_NAME);
    }

    @Test
    public void testUnpublishCertificate() throws IOException, CertificateException {
        List<Certificate> certificates = new ArrayList<Certificate>();
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificates.add(certificate);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certificates);
        entityCertificateManager.unPublishCertificate(SetUPData.ENTITY_NAME);
    }

    @Test(expected = CertificateServiceException.class)
    public void testUnpublishCertificate_certificateServiceException() throws IOException, CertificateException {

        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        entityCertificateManager.unPublishCertificate(SetUPData.ENTITY_NAME);
    }

}
