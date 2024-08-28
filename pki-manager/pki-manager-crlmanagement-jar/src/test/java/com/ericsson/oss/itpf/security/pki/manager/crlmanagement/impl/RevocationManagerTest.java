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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.RevocationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.RevocationRequestModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.Constants;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.eserviceref.CRLManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.TDPSUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.CoreEntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.revocation.helper.RevocationPersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.revocation.validator.RevocationValidator;

@RunWith(MockitoJUnitRunner.class)
public class RevocationManagerTest {

    @InjectMocks
    RevocationManager revocationManager;

    @Mock
    private Logger logger;

    @Mock
    RevocationPersistenceHelper revocationPersistenceHelper;

    @Mock
    RevocationService revocationService;

    @Mock
    RevocationRequestData revocationRequestData;

    @Mock
    RevocationValidator revocationValidator;

    @Mock
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Mock
    CertificateData certificateData;

    @Mock
    CertificateAuthorityData certificateAuthorityData;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CRLUnpublishNotifier crlUnpublishNotifier;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Mock
    TDPSUnpublishNotifier tdpsUnpublishNotifier;

    @Mock
    EntityInfoData entityInfoData;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    RevocationManagementAuthorizationManager revocationManagementAuthorizationManager;
    @Mock
    CoreEntitiesManager coreEntitiesManager;
    @Mock
    EntitiesModelMapperFactory modelMapperFactory;
    @Mock
    ModelMapper caEntityMapper;
    @Mock
    ModelMapper entityMapper;
    @Mock
    CAEntityMapper caEntMapper;
    @Mock
    EntityMapper entMapper;
    @Mock
    CRLManagerEServiceProxy crlManagerEServiceProxy;

    RevocationRequest revocationRequest;

    @Mock
    PersistenceManager persistenceManager;

    private String entityName;
    private String caEntityName;
    private EntityData entityData;
    private Date date;

    private Certificate certificate;
    private List<Certificate> certificateList;
    private List<Certificate> expiredCertList;
    private List<Certificate> revokedCertList;
    private List<Certificate> certList;
    private List<Certificate> certificatesListForInvalidSubFields;

    private CAEntityData caEntityData;
    private CAEntityData rootCAEntityData;
    private CAEntityData rootCASignedWithExternalCAData;
    private CertificateIdentifier certificateIdentifier;
    private DNBasedCertificateIdentifier dnBasedCertificateIdentifier;
    private SubjectField subjectFields = new SubjectField();
    final private Subject subject = new Subject();
    private List<CertificateData> certificateDatas;
    private List<Certificate> certificates;
    private static CertificateAuthority certificateAuthority;
    private static List<Certificate> inActiveCertificatesList;
    private static Certificate activeCertificate;
    private static List<CRLInfo> cRLInfoList;
    private CAEntity caEntity;
    private Entity entity;

    public static final String errorRevocationFailed = "Revocation Failed: Internal error occured";
    public static final String errorUpdateEntityStatus = "Exception while updating Entity Status";
    public static final String errorRetrievingCertificate = "Exception while retrieving certificate";

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() {

        entityName = "ENM_SubCA2";
        caEntityName = "ENM_CA";
        date = new Date();
        certificate = prepareActiveCertificate();
        certificateList = prepareActiveInactiveCertificateList();
        expiredCertList = prepareExpiredCertificateList();
        revokedCertList = prepareRevokedCertificateList();
        certList = prepareCertificateList();
        certificatesListForInvalidSubFields = prepareCertList();
        activeCertificate = CRLSetUpData.getCertificate(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);

        revocationManagementAuthorizationManager = new RevocationManagementAuthorizationManager();

        caEntityData = prepareCAEntityData();
        rootCAEntityData = prepareRootCAEntityData();
        rootCASignedWithExternalCAData = prepareRootCAEntityDataWithExternalCASigned();
        entityData = prepareEntityData();
        certificateIdentifier = prepareCertificateIdentifier();
        dnBasedCertificateIdentifier = prepareDNBasedCertificateIdentifier();
        final List<SubjectField> subjectField = new ArrayList<SubjectField>();
        subjectFields.setType(SubjectFieldType.COMMON_NAME);
        subjectFields.setValue("ARJ_Root");
        subjectField.add(subjectFields);
        subject.setSubjectFields(subjectField);

        revocationRequest = new RevocationRequest();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        revocationRequest.setEntity(entityInfo);

        caEntity = new CAEntity();
        CertificateAuthority certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        caEntity.setCertificateAuthority(certificateAuthority);

        entity = new Entity();
        entity.setEntityInfo(entityInfo);
        entity.getEntityInfo().setIssuer(getCertificateAuthority(CertificateStatus.ACTIVE, true));

        Mockito.when(crlManagerEServiceProxy.getRevocationService()).thenReturn(revocationService);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager#revokeEntityCertificates(java.lang.String, com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason, java.util.Date)}
     * .
     */
    @Test
    public void testRevokeEntityCertificates() throws Exception {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateList);
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);

        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);

    }

    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeEntityCertificatesThrowsCertificateNotFoundException() {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        try {
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                    .thenReturn(null);
        } catch (PersistenceException | CertificateException | IOException e) {
            Mockito.verify(logger).error(errorRetrievingCertificate, e.getMessage());
        }

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);

    }

    @Test(expected = ExpiredCertificateException.class)
    public void testRevokeEntityCertificatesThrowsExpiredCertificateException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(expiredCertList);

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);
    }

    @Test(expected = RevokedCertificateException.class)
    public void testRevokeEntityCertificatesThrowsRevokedCertificateException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(revokedCertList);

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);
    }

    /**
     * Method to test RevokeEntityCertificates PersistenceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeEntityCertificates_PersistenceException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new PersistenceException());

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeEntityCertificates CertificateException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeEntityCertificates_CertificateException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new CertificateException());

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeEntityCertificates IOException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeEntityCertificates_IOException() {
        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        try {
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                    .thenThrow(new IOException());
        } catch (CertificateException | IOException e) {
            Mockito.verify(logger).error(ErrorMessages.UNEXPECTED_ERROR, e.getMessage());
        }

        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeEntityCertificates for CertificateException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeEntityCertificates_InvalidEntityAttributeException() {
        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        try {
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                    .thenReturn(certificateList);
            Mockito.when(revocationRequestModelMapper.toAPIModel((RevocationRequestData) Mockito.anyObject())).thenThrow(new CertificateException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorRevocationFailed);
        }
        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);

        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);

    }

    /**
     * Method to test RevokeEntityCertificates for IOException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeEntityCertificates_IOExp() {

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        try {
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                    .thenReturn(certificateList);
            Mockito.when(revocationRequestModelMapper.toAPIModel((RevocationRequestData) Mockito.anyObject())).thenThrow(new IOException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorRevocationFailed);
        }
        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
    }

    public void testRevokeCAEntityCertificatesForCA_Entity() throws Exception {

        setUp();
        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatas)).thenReturn(certificates);
        Mockito.when(revocationRequestData.getCaEntity()).thenReturn(caEntityData);
        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);

        Mockito.verify(revocationPersistenceHelper).getCAEntityData(caEntityName);

    }

    @Test
    public void testRevokeEntityCertificatesForEntity() throws Exception {

        setUp();

        Mockito.when(revocationPersistenceHelper.getEntityData(entityName)).thenReturn(entityData);
        Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityName, false, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateList);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatas)).thenReturn(certificates);
        Mockito.when(revocationRequestData.getEntity()).thenReturn(entityData);
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        Mockito.when(entityData.getEntityInfoData().getName()).thenReturn(entityName);
        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getEntityData(entityName);

    }

    @Test(expected = RootCertificateRevocationException.class)
    public void testRevokeCAEntityCertificatesThrowsRootCertificateRevocationException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(rootCAEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateList);

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getCAEntityData(caEntityName);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCAEntityCertificatesThrowsCertificateNotFoundException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationPersistenceHelper).getCAEntityData(caEntityName);
    }

    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCAEntityCertificatesThrowsRevocationServiceException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new CertificateException());

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(caCertificatePersistenceHelper).getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * Method to test RevokeCAEntityCertificates WithEmptyCerificateList CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCAEntityCertificates_WithEmptyCerificateList_CertificateNotFoundException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(null);

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeCAEntityCertificates PersistenceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCAEntityCertificates_PersistenceException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new PersistenceException());

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeCAEntityCertificates CertificateException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCAEntityCertificates_CertificateException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new CertificateException());

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Method to test RevokeCAEntityCertificates IOException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCAEntityCertificates_IOException() throws Exception {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new IOException());

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager#revokeCertificate(com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier, com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason, java.util.Date)}
     * .
     * 
     * @throws IOException
     * @throws CertificateException
     */
    @Test
    public void testRevokeCertificateByIssuerName() throws CertificateException, IOException {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(revocationPersistenceHelper).getCertificate(certificateIdentifier);
    }

    @Test(expected = RootCertificateRevocationException.class)
    public void testRevokeCertificateByIssuerNameRootCertificateRevocationException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId()))
                .thenThrow(new RootCertificateRevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED));
        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(revocationPersistenceHelper).getCertificate(certificateIdentifier);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for EntityNotFoundException.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testRevokeCertificateByIssuerName_EntityNotFoundException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);

        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0,
                    CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorUpdateEntityStatus, e.getMessage());
        }

        Mockito.when(caEntMapper.toAPIFromModel(caEntityData, false)).thenReturn((caEntity));
        Mockito.when(caEntMapper.toAPIFromModelForSummary(caEntityData.getCertificateAuthorityData().getIssuer())).thenReturn(caEntity);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(caEntityMapper);
        Mockito.doThrow(new EntityNotFoundException()).when(coreEntitiesManager).updateEntity(((CAEntity) Mockito.any()));

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
        Mockito.verify(revocationPersistenceHelper).getCertificate(certificateIdentifier);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for EntityServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCertificateByIssuerName_EntityServiceException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        final CertificateAuthority certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        caEntity.setCertificateAuthority(certificateAuthority);
        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0,
                    CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorUpdateEntityStatus, e.getMessage());
        }

        Mockito.when(caEntMapper.toAPIFromModel(caEntityData, false)).thenReturn(caEntity);
        Mockito.when(caEntMapper.toAPIFromModelForSummary(caEntityData.getCertificateAuthorityData().getIssuer())).thenReturn(caEntity);

        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(caEntityMapper);
        Mockito.doThrow(new EntityServiceException()).when(coreEntitiesManager).updateEntity(((CAEntity) Mockito.any()));

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for PersistenceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCertificateByIssuerName_PersistenceException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        final CertificateAuthority certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        caEntity.setCertificateAuthority(certificateAuthority);
        try {
            Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0,
                    CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(null);
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest)
                    .thenThrow(new CertificateException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorRetrievingCertificate, e.getMessage());
            e.printStackTrace();
        }

        Mockito.when(caEntMapper.toAPIFromModel(caEntityData, false)).thenReturn((caEntity));
        Mockito.when(caEntMapper.toAPIFromModelForSummary(caEntityData.getCertificateAuthorityData().getIssuer())).thenReturn(caEntity);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(caEntityMapper);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(caEntityData);

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test RevokeCertificateByIssuerName for CertificateException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCertificateByIssuerName_CertificateException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        final CertificateAuthority certificateAuthority = getCertificateAuthority(CertificateStatus.ACTIVE, true);
        caEntity.setCertificateAuthority(certificateAuthority);
        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0, 
                    CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(new CertificateException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(ErrorMessages.UNEXPECTED_ERROR + e);
        }
        Mockito.when(caEntMapper.toAPIFromModel(caEntityData, false)).thenReturn((caEntity));
        Mockito.when(caEntMapper.toAPIFromModelForSummary(caEntityData)).thenReturn(caEntity);
        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for IOException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCertificateByIssuerName_IOException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);

        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityData.getCertificateAuthorityData().getName(), MappingDepth.LEVEL_0,
                    CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(new IOException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(ErrorMessages.UNEXPECTED_ERROR, e.getMessage());
        }

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for EntityNotFoundException.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testRevokeCertByIssuerNameUpdateEntityStatus_EntityNotFoundException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);

        try {
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE,
                    CertificateStatus.INACTIVE)).thenReturn(null);
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error("Exception while updating Entity Status", e.getMessage());
        }
        
        Mockito.when(entMapper.toAPIFromModelForSummary(Mockito.any(EntityData.class))).thenReturn(entity);
        Mockito.when(caEntMapper.toAPIFromModelForSummary(entityData.getEntityInfoData().getIssuer())).thenReturn(caEntity);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entityMapper);
        Mockito.doThrow(new EntityNotFoundException()).when(coreEntitiesManager).updateEntity(((Entity) Mockito.any()));

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
        Mockito.verify(revocationPersistenceHelper).getCertificate(certificateIdentifier);
    }

    /**
     * Method to test RevokeCertificateByIssuerName for EntityServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCertByIssuerNameUpdateEntityStatus_EntityServiceException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);

        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE,
                    CertificateStatus.INACTIVE)).thenReturn(null);
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error("Exception while updating Entity Status", e.getMessage());
        }

        Mockito.when(entMapper.toAPIFromModelForSummary(Mockito.any(EntityData.class))).thenReturn(entity);
        Mockito.when(caEntMapper.toAPIFromModelForSummary(entityData.getEntityInfoData().getIssuer())).thenReturn(caEntity);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entityMapper);
        Mockito.doThrow(new EntityServiceException()).when(coreEntitiesManager).updateEntity(((Entity) Mockito.any()));

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for PersistenceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCertByIssuerNameUpdateEntityStatus_PersistenceException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);

        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE,
                    CertificateStatus.INACTIVE)).thenReturn(null);
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(errorRetrievingCertificate, e.getMessage());
        }
        Mockito.when(entMapper.toAPIFromModelForSummary(Mockito.any(EntityData.class))).thenReturn(entity);
        Mockito.when(caEntMapper.toAPIFromModelForSummary(entityData.getEntityInfoData().getIssuer())).thenReturn(caEntity);
        Mockito.when(modelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entityMapper);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(entityData);

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for CertificateException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCertByIssuerNameUpdateEntityStatus_CertificateException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);

        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE,
                    CertificateStatus.INACTIVE)).thenThrow(new CertificateException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(ErrorMessages.UNEXPECTED_ERROR + e);
        }

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    /**
     * Method to test RevokeCertificateByIssuerName for IOException.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testRevokeCertByIssuerNameUpdateEntityStatus_IOException() {

        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);
        try {
            Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
            Mockito.when(entityCertificatePersistenceHelper.getCertificates(entityData.getEntityInfoData().getName(), MappingDepth.LEVEL_0, CertificateStatus.ACTIVE,
                    CertificateStatus.INACTIVE)).thenThrow(new IOException());
        } catch (CertificateException | PersistenceException | IOException e) {
            Mockito.verify(logger).error(ErrorMessages.UNEXPECTED_ERROR, e.getMessage());
        }

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

    }

    @Test
    public void testRevokeCertificateBySubjectDn() throws CertificateException, IOException {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(revocationPersistenceHelper, times(1)).getCertificateList(dnBasedCertificateIdentifier);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with EntityNotFoundException
     */
    @Test(expected = EntityNotFoundException.class)
    public void testRevokeCertificateBySubjectDn_EntityNotFoundException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException()).when(revocationService)
                .revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCertificateBySubjectDn_CertificateNotFoundException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException(
                "No ACTIVE certificate found")).when(revocationService).revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with ExpiredCertificateException.
     */
    @Test(expected = ExpiredCertificateException.class)
    public void testRevokeCertificateBySubjectDn_ExpiredCertificateException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException("Certificate has expired"))
                .when(revocationService).revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with RevokedCertificateException.
     */
    @Test(expected = RevokedCertificateException.class)
    public void testRevokeCertificateBySubjectDn_RevokedCertificateException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException("Certificate is already revoked"))
                .when(revocationService).revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with RootCertificateRevocationException.
     *
     */
    @Test(expected = RootCertificateRevocationException.class)
    public void testRevokeCertificateByDN_RootCertificateRevocationException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certList);

        Mockito.doThrow(new RootCertificateRevocationException("Root CA can not be revoked")).when(revocationService)
                .revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with CertificateNotFoundException.
     *
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCertificateByDN_CertificateNotFoundException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificatesListForInvalidSubFields);

        Mockito.doThrow(new CertificateNotFoundException("The certificate with given subject and issuerdn is not found ")).when(revocationService)
                .revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with RootCertificateRevocationException.
     *
     */
    @Test(expected = RootCertificateRevocationException.class)
    public void testRevokeCertificateByDN_RootCertificateRevokedException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(rootCAEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());

        Mockito.doThrow(new RootCertificateRevocationException("Root CA can not be revoked")).when(revocationService)
                .revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with IssuerCertificateRevokedException.
     */
    @Test(expected = IssuerCertificateRevokedException.class)
    public void testRevokeCertificateBySubjectDn_IssuerCertificateRevokedException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificatePathValidationException("Issuer Certificate is revoked"))
                .when(revocationService).revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with RootCertificateRevocationException.
     */
    @Test(expected = RootCertificateRevocationException.class)
    public void testRevokeCertificateBySubjectDn_RootCertificateRevocationException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.revocation.RootCARevocationException("Root CA can not be revoked"))
                .when(revocationService).revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    /**
     * Method to test revokeCertificateBySubjectDn with RevocationServiceException.
     */
    @Test(expected = RevocationServiceException.class)
    public void testRevokeCertificateBySubjectDn_RevocationServiceException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException(
                "Exception occured while processing the revocation request")).when(revocationService)
                .revokeCertificate((RevocationRequest) Mockito.any());

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
    }

    @Test
    public void testRevokeCertificateBySubjectDnThrowsCertificateNotFoundException() throws CertificateException, IOException {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(caEntityData);
        Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(revocationPersistenceHelper, times(1)).getCertificateList(dnBasedCertificateIdentifier);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCertificateBySubjectDnCertificateNotFoundException() {
        Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenThrow(new CertificateNotFoundException());
        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(logger).error("Subject DN or IssuerDn not matched for the certificate with serial number "
                + dnBasedCertificateIdentifier.getCerficateSerialNumber());
    }

    @Test
    public void testRevokeCertificateCheckingForNullValueExecution() throws CertificateException, IOException {
        Mockito.when(revocationPersistenceHelper.getCertificate(certificateIdentifier)).thenReturn(certificate);
        Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(null);
        Mockito.when(revocationPersistenceHelper.getEntityById(certificate)).thenReturn(entityData);
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, RevocationReason.KEY_COMPROMISE, date);

        Mockito.verify(revocationPersistenceHelper, times(1)).getCertificate(certificateIdentifier);
        Mockito.verify(revocationPersistenceHelper, times(1)).getCaEntityById(certificate.getId());

    }

    @Test(expected = CertificateServiceException.class)
    public void testRevokeCAEntityCertificatesCertificateServiceException() throws CertificateException, PersistenceException, IOException {
        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenThrow(new CertificateServiceException());

        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testRevokeCertificateNotFoundException() throws CertificateException, IOException {
        Mockito.when(revocationRequestModelMapper.toAPIModel(revocationRequestData)).thenThrow(new CertificateNotFoundException());
        revocationManager.revokeEntityCertificates(entityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(revocationRequestModelMapper).toAPIModel(revocationRequestData);
    }

    @Test
    public void testRevokeCAEntityCertificatesForDefault() throws CertificateException, IOException {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateList);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatas)).thenThrow(new CertificateException());
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(caCertificatePersistenceHelper).getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    @Test
    public void testRevokeCAEntityCertificatesForDefaultThrowsCertificateException() throws CertificateException, IOException {

        Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(caEntityData);
        Mockito.when(revocationRequestModelMapper.toAPIModel(Mockito.any(RevocationRequestData.class))).thenReturn(revocationRequest);
        Mockito.when(caCertificatePersistenceHelper.getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateList);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatas)).thenThrow(new RevocationServiceException(caEntityName));
        revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        Mockito.verify(caCertificatePersistenceHelper).getCertificates(caEntityName, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    @Test
    public void testRevokeCAEntityCertificatesForRootCASignedWithExternalCA() throws CertificateException, IOException {

        try {
            Mockito.when(revocationPersistenceHelper.getCAEntityData(caEntityName)).thenReturn(rootCASignedWithExternalCAData);
            revocationManager.revokeCAEntityCertificates(caEntityName, RevocationReason.UNSPECIFIED, date);
        } catch (RootCertificateRevocationException e) {
            assertEquals(e.getMessage(), ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);
        }

    }

    @Test
    public void testRevokeCertificateBySubjectDnWithCASignedWithExternalCA() {
        try {
            Mockito.when(revocationPersistenceHelper.getCertificateList(dnBasedCertificateIdentifier)).thenReturn(certificateList);
            Mockito.when(revocationPersistenceHelper.getCaEntityById(certificate.getId())).thenReturn(rootCASignedWithExternalCAData);
            Mockito.when(revocationPersistenceHelper.getEntityIdFromCertificateId(certificate.getId())).thenReturn(certificate.getId());

            revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, RevocationReason.KEY_COMPROMISE, date);
        } catch (RootCertificateRevocationException e) {
            assertEquals(e.getMessage(), ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);
        }

    }

    private Certificate prepareActiveCertificate() {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setSubject(subject);
        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setSubject(subject);
        certificate.setIssuer(prepareCertificateAuthority());
        certificate.setIssuerCertificate(issuerCertificate);
        return certificate;
    }

    private Certificate prepareCertificate() {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setSubject(subject);
        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setSubject(subject);
        certificate.setIssuer(prepareIssuerCA());
        certificate.setIssuerCertificate(null);
        return certificate;
    }

    private Certificate prepareCert() {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setSubject(subject);
        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.ACTIVE);

        List<SubjectField> subjectField = new ArrayList<SubjectField>();
        Subject subject = new Subject();
        SubjectField subjectFields = new SubjectField();
        subjectFields.setType(SubjectFieldType.COMMON_NAME);
        subjectFields.setValue("ARJ_Root11");
        subjectField.add(subjectFields);
        subject.setSubjectFields(subjectField);

        certificate.setSubject(subject);
        certificate.setIssuer(prepareIssuerCA());
        certificate.setIssuerCertificate(issuerCertificate);
        return certificate;
    }

    private Certificate prepareRevokedCertificate() {

        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.REVOKED);

        return certificate;
    }

    private Certificate prepareExpiredCertificate() {

        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.EXPIRED);

        return certificate;
    }

    private Certificate prepareInactiveCertificate() {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setSubject(subject);
        Certificate certificate = new Certificate();
        certificate.setId(10101);
        certificate.setIssuedTime(date);
        certificate.setSerialNumber("35464474");
        certificate.setStatus(CertificateStatus.INACTIVE);
        certificate.setSubject(subject);
        certificate.setIssuer(prepareCertificateAuthority());
        certificate.setIssuerCertificate(issuerCertificate);
        return certificate;
    }

    private List<Certificate> prepareActiveInactiveCertificateList() {

        List<Certificate> certficateList = new LinkedList<Certificate>();
        certficateList.add(prepareActiveCertificate());
        certficateList.add(prepareInactiveCertificate());

        return certficateList;

    }

    private List<Certificate> prepareCertificateList() {

        List<Certificate> certficateList = new LinkedList<Certificate>();
        certficateList.add(prepareCertificate());
        return certficateList;
    }

    private List<Certificate> prepareCertList() {

        List<Certificate> certficateList = new LinkedList<Certificate>();
        certficateList.add(prepareCert());
        return certficateList;
    }

    private List<Certificate> prepareRevokedCertificateList() {

        List<Certificate> certficateList = new LinkedList<Certificate>();
        certficateList.add(prepareRevokedCertificate());

        return certficateList;

    }

    private List<Certificate> prepareExpiredCertificateList() {

        List<Certificate> certficateList = new LinkedList<Certificate>();
        certficateList.add(prepareExpiredCertificate());

        return certficateList;
    }

    private EntityData prepareEntityData() {

        EntityData entityData = new EntityData();
        entityData.setId(101010);
        entityData.setPublishCertificatetoTDPS(true);
        entityData.setEntityInfoData(entityInfoData);
        return entityData;
    }

    private CAEntityData prepareCAEntityData() {

        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setEntityProfileData(new EntityProfileData());
        caEntityData.setExternalCA(false);
        caEntityData.setId(101010101);
        caEntityData.setKeyGenerationAlgorithm(new AlgorithmData());
        caEntityData.setPublishCertificatetoTDPS(false);
        caEntityData.setCertificateAuthorityData(prepareCertificateAuthorityData());

        return caEntityData;
    }

    private CertificateAuthorityData prepareCertificateAuthorityData() {

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMCA");
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setSubjectAltName("AltName");
        certificateAuthorityData.setSubjectDN("SubDN");
        return certificateAuthorityData;
    }

    private CertificateAuthority prepareCertificateAuthority() {

        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(101);
        certificateAuthority.setName("ENMCA");
        certificateAuthority.setRootCA(false);
        certificateAuthority.setSubject(subject);
        return certificateAuthority;
    }

    /**
     * PrepareIssuerCA
     */
    private CertificateAuthority prepareIssuerCA() {

        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(101);
        certificateAuthority.setName("ENMCA");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setSubject(subject);
        return certificateAuthority;
    }

    private CertificateAuthorityData prepareRootCertificateAuthorityData() {

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMCA");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setSubjectAltName("AltName");
        certificateAuthorityData.setSubjectDN("");

        return certificateAuthorityData;
    }

    private CertificateAuthorityData prepareRootCertificateAuthorityDataWithExternalCASigned() {

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMCA");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setSubjectAltName("AltName");
        certificateAuthorityData.setSubjectDN("");
        certificateAuthorityData.setIssuerExternalCA(true);

        return certificateAuthorityData;
    }

    private CAEntityData prepareRootCAEntityData() {

        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setEntityProfileData(new EntityProfileData());
        caEntityData.setExternalCA(false);
        caEntityData.setId(101010101);
        caEntityData.setKeyGenerationAlgorithm(new AlgorithmData());
        caEntityData.setPublishCertificatetoTDPS(false);
        caEntityData.setCertificateAuthorityData(prepareRootCertificateAuthorityData());

        return caEntityData;
    }

    private CAEntityData prepareRootCAEntityDataWithExternalCASigned() {

        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setEntityProfileData(new EntityProfileData());
        caEntityData.setExternalCA(false);
        caEntityData.setId(101010101);
        caEntityData.setKeyGenerationAlgorithm(new AlgorithmData());
        caEntityData.setPublishCertificatetoTDPS(false);
        caEntityData.setCertificateAuthorityData(prepareRootCertificateAuthorityDataWithExternalCASigned());

        return caEntityData;
    }

    private CertificateIdentifier prepareCertificateIdentifier() {

        CertificateIdentifier certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName("issuerN");
        certificateIdentifier.setSerialNumber("565670");

        return certificateIdentifier;
    }

    private DNBasedCertificateIdentifier prepareDNBasedCertificateIdentifier() {
        dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setCerficateSerialNumber("565670");
        dnBasedCertificateIdentifier.setIssuerDN("CN=ARJ_Root");
        dnBasedCertificateIdentifier.setSubjectDN("CN=ARJ_Root");
        return dnBasedCertificateIdentifier;
    }

    /**
     * Method to get CertificateAuthority
     * 
     * @return CertificateAuthority
     */
    private CertificateAuthority getCertificateAuthority(final CertificateStatus status, final boolean isMatchingCertificate) {
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
    private Certificate getInActiveCertificate(final String serialNumber) {
        final Certificate inActiveCertificate = new Certificate();
        inActiveCertificate.setSerialNumber(serialNumber);
        inActiveCertificate.setStatus(CertificateStatus.INACTIVE);
        return inActiveCertificate;

    }
}
