/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

@RunWith(MockitoJUnitRunner.class)
public class ExportCSRHandlerTest {

    @InjectMocks
    GenerateCSRHandler exportCSRHandler;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    CAEntityData caEntityData;

    @Mock
    CAEntity caEntity;

    @Mock
    PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder;

    @Mock
    PKCS10CertificationRequest pKCS10CertificationRequest;

    @Mock
    CertificateManagementService coreCertificateManagementService;

    @Mock
    EntityHelper entityHelper;

    @Mock
    CertificateAuthority certificateAuthority;

    @Mock
    CertificateGenerationInfoBuilder certificateGenerationInfoBuilder;

    @Mock
    CertificateGenerationInfo certificateGenerationInfo;

    @Mock
    EntityPersistenceHandler<CAEntity> entityPersistenceHandler;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;
    

    private static String extCAName = "extCAName";
    private static byte[] encoded = new byte[] { 1 };

    Subject subject;

    @Before
    public void setUp() {

        subject = new Subject().fromASN1String("CN=RAVI");
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

    }

    @Test
    public void testExportCSRNewKey() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidOperationException,
            KeyPairGenerationException {

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);

        Mockito.when(caCertificatePersistenceHelper.getCAEntity("extCAName")).thenReturn(caEntityData);
        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        
        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.REKEY)).thenReturn(certificateGenerationInfo);
        PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = exportCSRHandler.generateCSR(extCAName, true);
        Assert.assertNotNull(pKCS10CertificationRequestHolder.getCertificateRequest());


    }

    @Test
    public void testExportCSROldKey() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidOperationException,
            KeyPairGenerationException {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenReturn(caEntityData);
        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, extCAName, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.RENEW)).thenReturn(certificateGenerationInfo);
        PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = exportCSRHandler.generateCSR(extCAName, false);

        Assert.assertNotNull(pKCS10CertificationRequestHolder.getCertificateRequest());

    }

    @Test(expected = CANotFoundException.class)
    public void testExportCSRCANotFoundException() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidOperationException,
            KeyPairGenerationException {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenThrow(new CANotFoundException());
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);

        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.ROOT_CA_NOT_FOUND);

    }

    /**
     * Test case for checking CANotFoundException is thrown when coreCertificateManagementService thrown CertificateAuthorityDoesNotExistException.
     * 
     * @throws Exception
     */
    @Test(expected = CANotFoundException.class)
    public void testExportCSRCertificateAuthorityDoesNotExistException() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException,
            InvalidOperationException, KeyPairGenerationException {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenReturn(caEntityData);

        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException("CertificateAuthorityDoesNotExistException"));
        Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.REKEY)).thenReturn(certificateGenerationInfo);
        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.ROOT_CA_NOT_FOUND);

    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSRCertificateRequestGenerationException() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException,
            InvalidOperationException, KeyPairGenerationException {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenReturn(caEntityData);

        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException("CSRGenerationException"));
        Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.REKEY)).thenReturn(certificateGenerationInfo);
        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.CSR_GENERATION_FAILED);

    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testExportCSRAlgorithmValidationException() throws Exception {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenReturn(caEntityData);

        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);
        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException("Algorithm Validation Exception"));
       Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.REKEY)).thenReturn(certificateGenerationInfo);
        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.CSR_GENERATION_FAILED);

    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSRCoreEntityServiceException() throws Exception {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenReturn(caEntityData);

        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Matchers.anyObject())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);

        Mockito.when(caEntity.getCertificateAuthority()).thenReturn(certificateAuthority);
        Mockito.when(certificateAuthority.getSubject()).thenReturn(subject);
        Mockito.when(caEntity.getCertificateAuthority().isRootCA()).thenReturn(true);
        Mockito.when(caEntity.getCertificateAuthority().getStatus()).thenReturn(CAStatus.ACTIVE);

        Mockito.when(coreCertificateManagementService.generateCSR((CertificateGenerationInfo) Mockito.anyObject())).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException("CSRGenerationException"));
        Mockito.when(certificateGenerationInfoBuilder.build(caEntity, RequestType.REKEY)).thenReturn(certificateGenerationInfo);
        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.CSR_GENERATION_FAILED);

    }

    

    @Test(expected = CertificateServiceException.class)
    public void testExportCSRPersistenceException() throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidOperationException,
            KeyPairGenerationException {

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(extCAName)).thenThrow(new EntityServiceException());

        exportCSRHandler.generateCSR(extCAName, true);

        Mockito.verify(logger).error(ErrorMessages.INTERNAL_ERROR);

    }

}
