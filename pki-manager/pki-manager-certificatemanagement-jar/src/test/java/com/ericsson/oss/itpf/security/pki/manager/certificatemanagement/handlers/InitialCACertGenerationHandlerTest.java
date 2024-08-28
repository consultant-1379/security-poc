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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.CertificateManagementBaseTest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

@RunWith(MockitoJUnitRunner.class)
public class InitialCACertGenerationHandlerTest extends CertificateManagementBaseTest {

    @InjectMocks
    InitialCACertGenerationHandler initialCertGenerationHandler;

    @Mock
    CertificateManagementService certificateManagementService;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    CertificateGenerationInfoBuilder certificateInfoBuilder;

    @Mock
    CertificateValidator certificateValidator;

    @Mock
    EntityHelper entityHelper;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    private static SetUPData setUPData;
    private static CertificateGenerationInfoSetUPData certificateGenerationInfoSetUPData;
    private static SubjectSetUPData subjectData;
    private static EntitySetUPData entitySetUPData;

    private static Certificate certificate;

    /**
     * Prepares initial set up required to run the test cases.
     *
     * @throws Exception
     */
    @Before
    public void setUP() {
        setUPData = new SetUPData();
        subjectData = new SubjectSetUPData();
        entitySetUPData = new EntitySetUPData();
        certificateGenerationInfoSetUPData = new CertificateGenerationInfoSetUPData();
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(certificateManagementService); 

    }

    @Test
    public void testGenerateCertificate_SubCA() throws Exception {

        final Subject subject = subjectData.getSubject("TCS", "PKI", "Ericsson");
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true);

        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.SUB_CA_NAME);
        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.NEW);
        Mockito.verify(certificateManagementService).createCertificate(certGenInfo);
        Mockito.verify(caPersistenceHelper).storeCertificate(SetUPData.SUB_CA_NAME, certGenInfo, certificate);
    }

    /**
     * Test case for Verifying the creation of certificate for SubCA. Keys are generated using the key generation algorithm set in Entity Profile.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate_entityProfileKeyGenerationAlgorithm() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();
        caEntity.getEntityProfile().setKeyGenerationAlgorithm(new Algorithm());

        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.SUB_CA_NAME);
        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.NEW);
        Mockito.verify(certificateManagementService).createCertificate(certGenInfo);
        Mockito.verify(caPersistenceHelper).storeCertificate(SetUPData.SUB_CA_NAME, certGenInfo, certificate);
    }

    /**
     * Test case for Verifying the creation of certificate for SubCA. Keys are generated using the key generation algorithm set in Certificate Profile.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCertificate_certificateProfileKeyGenerationAlgorithm() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();
        caEntity.getEntityProfile().setKeyGenerationAlgorithm(null);

        final List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();
        keygenerationAlgorithms.add(new Algorithm());
        caEntity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(keygenerationAlgorithms);

        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);

        Mockito.verify(entityHelper).getCAEntity(SetUPData.SUB_CA_NAME);
        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.NEW);
        Mockito.verify(certificateManagementService).createCertificate(certGenInfo);
        Mockito.verify(caPersistenceHelper).storeCertificate(SetUPData.SUB_CA_NAME, certGenInfo, certificate);
    }

    /**
     * Test case for checking CANotFoundException is thrown when given CAName is invalid
     *
     */
    @Test(expected = CANotFoundException.class)
    public void testGenerateCertificate_CAEntity_Not_Found() {

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenThrow(new CAEntityNotInternalException(CA_ENTITY_NOT_FOUND));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Method to test Occurrence of CANotFoundException.
     *
     * @return CANotFoundException
     *
     */
    @Test(expected = CANotFoundException.class)
    public void testGenerateCertificate_CANotFoundException() {

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenThrow(new CANotFoundException(CA_ENTITY_NOT_FOUND));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking InvalidCAException is thrown when trying to generate certificate for SubCA if issuer CA not having an ACTIVE certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGenerateCertificate_IssuerCA_Has_NoActiveCertificate() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        Mockito.doThrow(new InvalidCAException("Could not issue certificate because CAEntity " + SetUPData.ROOT_CA_NAME + " does not have an ACTIVE certificate")).when(certificateValidator)
                .validateIssuerChain(SetUPData.ROOT_CA_NAME);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateServiceException is thrown when trying to store certificate in database.
     *
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_DataException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);

        Mockito.doThrow(new PersistenceException("Exception while storing the certificate in database")).when(caPersistenceHelper)
                .storeCertificate(caEntity.getCertificateAuthority().getName(), certGenInfo, certificate);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when pki core thrown CertificateGenerationException.
     *
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_Core_Exception() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.NEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException(CERTIFICATE_GENERATION_FAILED));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when pki core thrown CertificateGenerationException.
     *
     * @throws Exception
     */
    @Test(expected = CANotFoundException.class)
    public void testGenerateCertificate_CoreEntityNotFoundException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.NEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException(ENTITY_NOT_FOUND));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateServiceException is thrown when pki core throws CertificateServiceException.
     *
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificateServiceException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.NEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException(CERTIFICATE_GENERATION_FAILED));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when pki core thrown InvalidCertificateExtensionsException.
     *
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_UnsupportedCertificateVersion() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.NEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException(INVALID_CERTIFICATE_EXTENSIONS));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);

    }

    /**
     * Test case for checking AlgorithmNotFoundException is thrown when pki core thrown ValidationException.
     *
     * @throws Exception
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testGenerateCertificate_Algorithm_Not_Found() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        mockEntityAndKeyGenAlgorithm(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertGenInfo(caEntity);

        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException(ALGORITHM_NOT_FOUND));

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);

    }

    /**
     * Test case for checking CertificateEncodingException.
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_Certificate_Encoding_Faliled() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        mockEntityAndKeyGenAlgorithm(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertGenInfo(caEntity);

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenReturn(certificate);

        Mockito.doThrow(new CertificateEncodingException(CERTIFICATE_ENCODING_FAILED)).when(caPersistenceHelper)
                .storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    /**
     * Test case for checking CertificateException.
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_Certificate_Generation_Faliled() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new PersistenceException()).when(certificateValidator).validateIssuerChain(SetUPData.ROOT_CA_NAME);

        initialCertGenerationHandler.generateCertificate(SetUPData.SUB_CA_NAME);
    }

    private CertificateGenerationInfo mockGenerateCertificate(final CAEntity caEntity) throws Exception {

        mockEntityAndKeyGenAlgorithm(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertGenInfo(caEntity);

        mockCertificate(caEntity, certificateGenerationInfo);

        return certificateGenerationInfo;
    }

    private Certificate mockCertificate(final CAEntity caEntity, final CertificateGenerationInfo certificateGenerationInfo) throws IOException, CertificateException, CertificateEncodingException {

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(certificateManagementService.createCertificate(certificateGenerationInfo)).thenReturn(certificate);

        Mockito.doNothing().when(caPersistenceHelper).storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

        return certificate;
    }

    private CertificateGenerationInfo mockCertGenInfo(final CAEntity caEntity) throws Exception {

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.NEW)).thenReturn(certificateGenerationInfo);

        Mockito.doNothing().when(caPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);
        return certificateGenerationInfo;
    }

    private void mockEntityAndKeyGenAlgorithm(final CAEntity caEntity) throws CertificateException, IOException {

        Mockito.when(entityHelper.getCAEntity(caEntity.getCertificateAuthority().getName())).thenReturn(caEntity);

        Mockito.doNothing().when(certificateValidator).validateIssuerChain(SetUPData.SUB_CA_NAME);

        final Algorithm keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(caEntity)).thenReturn(keyGenerationAlgorithm);
    }

}
