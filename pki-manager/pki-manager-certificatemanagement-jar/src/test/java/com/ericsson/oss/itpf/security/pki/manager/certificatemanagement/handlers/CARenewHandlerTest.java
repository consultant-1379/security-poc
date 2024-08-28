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

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.ALGORITHM_NOT_FOUND;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CERTIFICATE_ENCODING_FAILED;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CERTIFICATE_GENERATION_FAILED;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.ENTITY_NOT_FOUND;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.CertificateGenerationInfoSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.EntitySetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SubjectSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

@RunWith(MockitoJUnitRunner.class)
public class CARenewHandlerTest {

    @InjectMocks
    CARenewHandler renewHandler;

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
    CAHierarchyPersistenceHandler caHierarchyPersistenceHandler;

    @Mock
    EntitiesModelMapperFactory modelMapperFactory;

    @Mock
    ModelMapper modelMapper;

    @Mock
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;


    private static SetUPData setUPData;
    private static CertificateGenerationInfoSetUPData certificateGenerationInfoSetUPData;
    private static SubjectSetUPData subjectData;
    private static EntitySetUPData entitySetUPData;

    private static Certificate certificate;
    private static CertificateAuthorityData certificateAuthorityData;
    private static CAEntityData caEntityData;

    public static final String COMMON_NAME = "TCS";
    public static final String ORGANIZATION_UNIT = "PKI";
    public static final String ORGANIZATION = "Ericsson";

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
        caEntityData = new CAEntityData();
        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("cADName");

        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(certificateManagementService);

    }

    /**
     * Test case to verify the creation of certificate for SubCA
     *
     * @throws Exception
     */
    @Test
    public void testRenewCACertificate() throws Exception {

        final Subject subject = subjectData.getSubject("TCS", "PKI", "Ericsson");
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true);

        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);

        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.RENEW);
        Mockito.verify(certificateManagementService).renewCertificate(certGenInfo);
        Mockito.verify(caPersistenceHelper).storeCertificate(SetUPData.SUB_CA_NAME, certGenInfo, certificate);
    }

    @Test
    public void testRenewCAandSubCACertificate() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException,
            IOException, DatatypeConfigurationException {
        final Subject subject = subjectData.getSubject(COMMON_NAME, ORGANIZATION_UNIT, ORGANIZATION);
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true);
        final CAEntity subCA = entitySetUPData.getCAEntity();
        final CertificateGenerationInfo certGenInfo = mockGenerateCertificate(caEntity);
        final CertificateGenerationInfo certificateGenerationInfo = mockGenerateCertificate(subCA);

        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        final List<CAEntityData> childCAs = new ArrayList<CAEntityData>();
        childCAs.add(caEntityData);

        Mockito.when(caHierarchyPersistenceHandler.getSubCAEntities(caPersistenceHelper.getCAEntity(caEntity.getCertificateAuthority().getName()))).thenReturn(childCAs);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapper);
        Mockito.when(modelMapper.toAPIFromModel(caEntityData)).thenReturn(subCA);
        Mockito.when(certificateManagementService.renewCertificate(certGenInfo)).thenReturn(certificate);
        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenReturn(certificate);
        renewHandler.renewCertificate(caEntity, ReIssueType.CA_WITH_IMMEDIATE_SUB_CAS);

        Mockito.verify(certificateManagementService).renewCertificate(certGenInfo);
    }

    @Test
    public void testrenewCAAndHierarchy() throws Exception {
        final Subject subject = subjectData.getSubject(COMMON_NAME, ORGANIZATION_UNIT, ORGANIZATION);
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true);
        final CertificateGenerationInfo certificateGenerationInfo = mockGenerateCertificate(caEntity);

        TreeNode<CAEntity> caHierarchy = new TreeNode<CAEntity>();
        TreeNode<CAEntity> subHierarchy = new TreeNode<CAEntity>();
        TreeNode<CAEntity> thirdSubHierarchy = new TreeNode<CAEntity>();

        subHierarchy.setData(caEntity);
        thirdSubHierarchy.setData(caEntity);

        final List<TreeNode<CAEntity>> childs = new ArrayList<TreeNode<CAEntity>>();
        final List<TreeNode<CAEntity>> subChilds = new ArrayList<TreeNode<CAEntity>>();

        subChilds.add(thirdSubHierarchy);
        subHierarchy.setChilds(subChilds);
        childs.add(subHierarchy);
        caHierarchy.setChilds(childs);

        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenReturn(certificate);
        Mockito.when(caHierarchyPersistenceHandler.getCAHierarchyByName(caEntity.getCertificateAuthority().getName())).thenReturn(caHierarchy);

        renewHandler.renewCertificate(caEntity, ReIssueType.CA_WITH_ALL_CHILD_CAS);

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

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);

        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.RENEW);
        Mockito.verify(certificateManagementService).renewCertificate(certGenInfo);
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

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);

        Mockito.verify(certificateInfoBuilder).build(caEntity, RequestType.RENEW);
        Mockito.verify(certificateManagementService).renewCertificate(certGenInfo);
        Mockito.verify(caPersistenceHelper).storeCertificate(SetUPData.SUB_CA_NAME, certGenInfo, certificate);
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

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
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

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
    }

    /**
     * Test case for checking CertificateGenerationException is thrown when pki co re thrown CertificateGenerationException.
     *
     * @throws Exception
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificate_Core_Exception() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.RENEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException(CERTIFICATE_GENERATION_FAILED));

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
    }

    /**
     * Test case for checking CANotFoundException is thrown when pki core throws CoreEntityNotFoundException.
     *
     * @throws Exception
     */
    @Test(expected = CANotFoundException.class)
    public void testGenerateCertificateEntityNotFoundException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.RENEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException(ENTITY_NOT_FOUND));

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
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
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.RENEW)).thenReturn(certificateGenerationInfo);

        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException(INVALID_CERTIFICATE_EXTENSIONS));

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);

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

        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException(ALGORITHM_NOT_FOUND));

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);

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
        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenReturn(certificate);

        Mockito.doThrow(new CertificateEncodingException(CERTIFICATE_ENCODING_FAILED)).when(caPersistenceHelper)
                .storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
    }

    /**
     * Test case for checking CertificateException.
     */
    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_Certificate_Generation_Faliled() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);
        Mockito.doThrow(new PersistenceException()).when(certificateValidator).validateIssuerChain(SetUPData.ROOT_CA_NAME);

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
    }

    @Test(expected = CANotFoundException.class)
    public void testGenerateCertificate_EntityNotFoundException() throws Exception {

        final CAEntity caEntity = entitySetUPData.getCAEntity();

        mockEntityAndKeyGenAlgorithm(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertGenInfo(caEntity);

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenReturn(certificate);

        Mockito.doThrow(new EntityNotFoundException()).when(caPersistenceHelper).storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

        renewHandler.renewCertificate(caEntity, ReIssueType.CA);
    }

    private CertificateGenerationInfo mockGenerateCertificate(final CAEntity caEntity) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException,
            NoSuchProviderException, OperatorCreationException, DatatypeConfigurationException {

        mockEntityAndKeyGenAlgorithm(caEntity);

        final CertificateGenerationInfo certificateGenerationInfo = mockCertGenInfo(caEntity);

        mockCertificate(caEntity, certificateGenerationInfo);

        return certificateGenerationInfo;
    }

    private Certificate mockCertificate(final CAEntity caEntity, final CertificateGenerationInfo certificateGenerationInfo) throws IOException, CertificateException, CertificateEncodingException {

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        Mockito.when(certificateManagementService.renewCertificate(certificateGenerationInfo)).thenReturn(certificate);

        Mockito.doNothing().when(caPersistenceHelper).storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

        return certificate;
    }

    private CertificateGenerationInfo mockCertGenInfo(final CAEntity caEntity) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
            OperatorCreationException, DatatypeConfigurationException, IOException, CertificateException {

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();
        Mockito.when(certificateInfoBuilder.build(caEntity, RequestType.RENEW)).thenReturn(certificateGenerationInfo);

        Mockito.doNothing().when(caPersistenceHelper).storeCertificateGenerateInfo(certificateGenerationInfo);
        return certificateGenerationInfo;
    }

    private void mockEntityAndKeyGenAlgorithm(final CAEntity caEntity) throws CertificateException, IOException {

        Mockito.doNothing().when(certificateValidator).verifyEntityStatusForReissue(caEntity);
        Mockito.doNothing().when(certificateValidator).validateIssuerChain(SetUPData.SUB_CA_NAME);

        final Algorithm keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        Mockito.when(entityHelper.getOverridenKeyGenerationAlgorithm(caEntity)).thenReturn(keyGenerationAlgorithm);
    }
}
