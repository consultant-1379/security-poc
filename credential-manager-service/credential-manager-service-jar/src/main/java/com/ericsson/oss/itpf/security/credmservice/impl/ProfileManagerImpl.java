/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.PKIEntityFactory;
import com.ericsson.oss.itpf.security.credmservice.api.PKIProfileFactory;
import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCANotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerSNNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCALists;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;
import com.ericsson.oss.services.security.pkimock.api.MockProfileManagementService;

@Stateless
public class ProfileManagerImpl implements ProfileManager {

    private static final Logger log = LoggerFactory.getLogger(ProfileManagerImpl.class);

    @Inject
    private SystemRecorderWrapper systemRecorder;

    @Inject
    private ContextService ctxService;

    @EServiceRef
    ProfileManagementService pkiProfileManager;

    @EServiceRef
    MockProfileManagementService mockProfileManager;

    @EServiceRef
    EntityManagementService pkiEntityManager;

    @EServiceRef
    MockEntityManagementService mockEntityManager;

    // put here interface name
    private final String className = this.getClass().getInterfaces()[0].getSimpleName();

    @Override
    public boolean isEntityPresent(final String entityName)
            throws CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {
        boolean ret = false;
        this.systemRecorder.recordCommand("isEntityPresent", CommandPhase.STARTED, this.className, entityName, null);
        try {
            ret = !this.getEntityManager().isEntityNameAvailable(entityName, EntityType.ENTITY);
        } catch (final EntityServiceException e) {
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final InvalidEntityException e) {
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        }
        this.systemRecorder.recordCommand("isEntityPresent", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityName, null);

        return ret;
    }

    private boolean isCAEntityPresent(final String caEntityName)
            throws CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {
        boolean ret = false;
        this.systemRecorder.recordCommand("isCAEntityPresent", CommandPhase.STARTED, this.className, caEntityName, null);
        try {
            ret = !this.getEntityManager().isEntityNameAvailable(caEntityName, EntityType.CA_ENTITY);
        } catch (final EntityServiceException e) {
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final InvalidEntityException e) {
            throw new CredentialManagerInvalidEntityException(e.getMessage());
        }
        this.systemRecorder.recordCommand("isCAEntityPresent", CommandPhase.FINISHED_WITH_SUCCESS, this.className, caEntityName, null);

        return ret;
    }

    @Override
    public CredentialManagerEntity createEntity(final String entityName, final CredentialManagerSubject subject,
            final CredentialManagerSubjectAltName subjectAltName,
            final CredentialManagerAlgorithm keyGenerationAlgorithm, final String entityProfileName)
                    throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {
        try {

            final PKIEntityFactory eeFactory = new PKIEntityFactoryImpl();
            final Entity endEntityCreate = eeFactory.setName(entityName).setSubject(subject).setSubjectAltName(subjectAltName)
                    .setEntityProfileName(entityProfileName).setKeyGenerationAlgorithm(keyGenerationAlgorithm).buildForCreate();

            this.systemRecorder.recordCommand("createEntity", CommandPhase.STARTED, this.className, entityName, null);

            Entity pkiEntity;
            try {
                pkiEntity = this.getEntityManager().createEntity(endEntityCreate);
            } catch (final InvalidSubjectAltNameExtension e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidSubjectException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final MissingMandatoryFieldException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final EntityCategoryNotFoundException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidEntityCategoryException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final EntityAlreadyExistsException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidEntityAttributeException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidProfileException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final ProfileNotFoundException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final UnsupportedCRLVersionException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final CRLExtensionException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidCRLGenerationInfoException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final CRLGenerationException e) {
                this.systemRecorder.recordError("CredentialManagerCRLServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final InvalidEntityException e) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        e.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
            } catch (final AlgorithmNotFoundException ex) {
                this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName,
                        ex.getMessage());
                throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
            }

            this.systemRecorder.recordCommand("createEntity", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityName, null);

            return PKIModelMapper.credMEndEntityFrom(pkiEntity);

        } catch (final IllegalArgumentException ex) {
            this.systemRecorder.recordError("IllegalArgumentException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidArgumentException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityServiceException ex) {
            this.systemRecorder.recordError("EntityServiceExcetion", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final CredentialManagerInvalidEntityException ex) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());

        }
    }

    @Override
    public CredentialManagerEntity getEntity(final String entityName) throws CredentialManagerInvalidArgumentException,
    CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        try {
            final PKIEntityFactory eeFactory = new PKIEntityFactoryImpl();
            final Entity endEntityRequest = eeFactory.setName(entityName).buildForRequest();
            this.systemRecorder.recordCommand("getEntity", CommandPhase.STARTED, this.className, entityName, null);

            final Entity pkiEndEntity = this.getEntityManager().getEntity(endEntityRequest);
            this.systemRecorder.recordCommand("getEntity", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityName, null);

            return PKIModelMapper.credMEndEntityFrom(pkiEndEntity);

        } catch (final IllegalArgumentException ex) {
            this.systemRecorder.recordError("IllegalArgumentException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidArgumentException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityServiceException ex) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityNotFoundException ex) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerEntityNotFoundException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final CredentialManagerInvalidEntityException ex) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
        }
    }

    @Override
    public CredentialManagerEntity updateEntity(final String entityName, final CredentialManagerSubject subject,
            final CredentialManagerSubjectAltName subjectAltName,
            final CredentialManagerAlgorithm keyGenerationAlgorithm, final String endEntityProfileName)
                    throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException,
                    CredentialManagerProfileNotFoundException, CredentialManagerEntityNotFoundException {

        try {
            PKIEntityFactory eeFactory = new PKIEntityFactoryImpl();

            final Entity endEntityRequest = eeFactory.setName(entityName).buildForRequest();
            Entity pkiEntity = this.getEntityManager().getEntity(endEntityRequest);

            log.debug("Entity before update: {}", pkiEntity);

            eeFactory = eeFactory.setEntity(pkiEntity);
            final Entity endEntityUpdate = eeFactory.setSubject(subject).setSubjectAltName(subjectAltName).setEntityProfileName(endEntityProfileName)
                    .setKeyGenerationAlgorithm(keyGenerationAlgorithm).buildForUpdate();

            this.systemRecorder.recordCommand("updateEntity", CommandPhase.STARTED, this.className, endEntityUpdate.getEntityInfo().getName(), null);
            log.debug("Entity to update: {}", endEntityUpdate);
            pkiEntity = this.getEntityManager().updateEntity(endEntityUpdate);
            this.systemRecorder.recordCommand("updateEntity", CommandPhase.FINISHED_WITH_SUCCESS, this.className,
                    endEntityUpdate.getEntityInfo().getName(), null);
            return PKIModelMapper.credMEndEntityFrom(pkiEntity);
        } catch (final EntityServiceException ex) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityNotFoundException ex) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerEntityNotFoundException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final ProfileNotFoundException ex) {
            this.systemRecorder.recordError("ProfileNotFoundException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerProfileNotFoundException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final CredentialManagerInvalidEntityException ex) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final AlgorithmNotFoundException ex) {
            this.systemRecorder.recordError("EntityServiceExcetion", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final InvalidSubjectAltNameExtension e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidSubjectException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final MissingMandatoryFieldException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final EntityCategoryNotFoundException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidEntityCategoryException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final EntityAlreadyExistsException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidProfileException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final UnsupportedCRLVersionException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final CRLExtensionException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidCRLGenerationInfoException e) {
            this.systemRecorder.recordError("CredentialManagerInternalServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final CRLGenerationException e) {
            this.systemRecorder.recordError("CredentialManagerCRLServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        }

    }

    @Override
    public CredentialManagerProfileInfo getProfile(final String entityProfileName) throws CredentialManagerInvalidArgumentException,
    CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        CertificateProfile pkiCertProfile = null;
        EntityProfile pkiEntityProfile = null;
        try {
            this.systemRecorder.recordCommand("getProfile", CommandPhase.STARTED, this.className, entityProfileName, null);

            pkiEntityProfile = (EntityProfile) this.getProfile(entityProfileName, ProfileType.ENTITY_PROFILE);

            this.systemRecorder.recordCommand("getProfile", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityProfileName, null);
            this.systemRecorder.recordCommand("getProfile", CommandPhase.STARTED, this.className, pkiEntityProfile.getCertificateProfile().getName(),
                    null);

            pkiCertProfile = (CertificateProfile) this.getProfile(pkiEntityProfile.getCertificateProfile().getName(),
                    ProfileType.CERTIFICATE_PROFILE);

            this.systemRecorder.recordCommand("getProfile", CommandPhase.FINISHED_WITH_SUCCESS, this.className,
                    pkiEntityProfile.getCertificateProfile().getName(), null);

        } catch (final CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException
                | CredentialManagerProfileNotFoundException e) {
            this.systemRecorder.recordError("CredentialManagerServiceException", ErrorSeverity.ERROR, this.className, entityProfileName, e.getMessage());
            throw e;
        }

        return PKIModelMapper.credMProfileInfoFrom(pkiEntityProfile, pkiCertProfile);

    }

    private AbstractProfile getProfile(final String name, final ProfileType type) throws CredentialManagerInvalidArgumentException,
    CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException {
        final PKIProfileFactory epFactory = new PKIProfileFactoryImpl();
        AbstractProfile entityProfileRequest;

        entityProfileRequest = epFactory.setName(name).setProfileType(type).buildForRequest();

        AbstractProfile pkiProfile = null;

        try {
            pkiProfile = this.getProfileManager().getProfile(entityProfileRequest);
        } catch (final IllegalArgumentException ex) {
            throw new CredentialManagerInvalidArgumentException("Entity Profile : " + name + " - " + ex.getMessage());
        } catch (final ProfileServiceException ex) {
            throw new CredentialManagerInternalServiceException("Entity Profile : " + name + " - " + ex.getMessage());
        } catch (final ProfileNotFoundException ex) {
            throw new CredentialManagerProfileNotFoundException("Entity Profile : " + name + " - " + ex.getMessage());
        } catch (final InvalidProfileAttributeException ex) {
            throw new CredentialManagerInvalidProfileException("Entity Profile : " + name + " - " + ex.getMessage());
        } catch (final MissingMandatoryFieldException ex) {
            throw new CredentialManagerInvalidProfileException("Entity Profile : " + name + " - " + ex.getMessage());
        } catch (final InvalidProfileException ex) {
            throw new CredentialManagerInvalidProfileException("Entity Profile : " + name + " - " + ex.getMessage());
        }

        return pkiProfile;
    }

    @Override
    public CredentialManagerCALists getTrustCAList(final String entityProfileName) throws CredentialManagerInvalidArgumentException,
    CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerInternalServiceException {

        CredentialManagerCALists caLists = new CredentialManagerCALists();

        this.systemRecorder.recordCommand("getTrustCAList", CommandPhase.STARTED, this.className, entityProfileName, null);

        EntityProfile pkiEntityProfile = null;
        try {
            pkiEntityProfile = (EntityProfile) this.getProfile(entityProfileName, ProfileType.ENTITY_PROFILE);
        } catch (final CredentialManagerInvalidArgumentException | CredentialManagerInternalServiceException
                | CredentialManagerProfileNotFoundException | CredentialManagerInvalidProfileException e) {
            this.systemRecorder.recordError("CredentialManagerServiceException", ErrorSeverity.ERROR, this.className, entityProfileName, e.getMessage());
            throw e;
        }
        try {
            for (final TrustProfile trustProfile : pkiEntityProfile.getTrustProfiles()) {

                // recall get for single TrustProfile
                caLists = this.getTrustCAListFromTP(trustProfile.getName(), caLists);

            }
        } catch (final CredentialManagerServiceException e) {
            this.systemRecorder.recordError("CredentialManagerServiceException", ErrorSeverity.ERROR, this.className, entityProfileName, e.getMessage());
            throw new CredentialManagerInternalServiceException(e);
        }
        this.systemRecorder.recordCommand("getTrustCAList", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityProfileName, null);
        return caLists;
    }

    @Override
    public CredentialManagerCALists getTrustCAListFromTP(final String trustProfileName, CredentialManagerCALists caLists)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException {

        this.systemRecorder.recordCommand("getTrustCAListFromTP", CommandPhase.STARTED, this.className, trustProfileName, null);

        if (caLists == null) {
            caLists = new CredentialManagerCALists();
        }
        final TrustProfile pkiTrustProfile = (TrustProfile) this.getProfile(trustProfileName, ProfileType.TRUST_PROFILE);
        CredentialManagerTrustCA trustCA = null;
        for (final TrustCAChain trustIntCA : pkiTrustProfile.getTrustCAChains()) {
            trustCA = new CredentialManagerTrustCA(trustIntCA.getInternalCA().getCertificateAuthority().getName(), trustIntCA.isChainRequired());
            caLists.getInternalCAList().add(trustCA);
        }
        for (final ExtCA trustExtCA : pkiTrustProfile.getExternalCAs()) {
            //external CA does not support isChainRequired flag, so we force it to false
            trustCA = new CredentialManagerTrustCA(trustExtCA.getCertificateAuthority().getName(), false);
            caLists.getExternalCAList().add(trustCA);
        }
        return caLists;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.ProfileManager# getEntitiesByCategory(java.lang.String)
     */
    @Override
    public Set<CredentialManagerEntity> getEntitiesByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        this.systemRecorder.recordCommand("getEntitiesByCategory", CommandPhase.STARTED, this.className, categoryName, null);

        List<Entity> pkiEntityList;
        try {
            pkiEntityList = this.getPkiEntitiesByCategory(categoryName);
        } catch (final CredentialManagerInvalidEntityException e) {
            throw new CredentialManagerInvalidArgumentException(e);
        }

        // trasform the list in set
        final Set<CredentialManagerEntity> entitySet = this.listEntityToSetCredentialManagerEntity(pkiEntityList);
        return entitySet;

    } // end of getEntitiesByCategory

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.ProfileManager# getEntitiesByCategory(java.lang.String)
     */
    @Override
    public Set<CredentialManagerEntity> getEntitiesSummaryByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {

        this.systemRecorder.recordCommand("getEntitiesSummaryByCategory", CommandPhase.STARTED, this.className, categoryName, null);

        List<Entity> pkiEntityList;
        try {
            pkiEntityList = this.getPkiEntitiesSummaryByCategory(categoryName);
        } catch (final CredentialManagerInvalidEntityException e) {
            throw new CredentialManagerInvalidArgumentException(e);
        }

        // trasform the list in set
        final Set<CredentialManagerEntity> entitySet = this.listEntitySummaryToSetCredentialManagerEntity(pkiEntityList);
        return entitySet;

    } // end of getEntitiesByCategory


    /**
     * @param pkiEntityList
     * @return
     */
    private Set<CredentialManagerEntity> listEntityToSetCredentialManagerEntity(final List<Entity> pkiEntityList)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {
        final Set<CredentialManagerEntity> entitySet = new HashSet<CredentialManagerEntity>();
        final Iterator<Entity> iterator = pkiEntityList.iterator();
        while (iterator.hasNext()) {
            try {
                entitySet.add(PKIModelMapper.credMEndEntityFrom(iterator.next()));
            } catch (final CredentialManagerInvalidEntityException e) {
                throw new CredentialManagerInvalidArgumentException(e);
            }
        }
        return entitySet;
    }

    /**
     * @param pkiEntityList
     * @return
     */
    private Set<CredentialManagerEntity> listEntitySummaryToSetCredentialManagerEntity(final List<Entity> pkiEntityList)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {
        final Set<CredentialManagerEntity> entitySet = new HashSet<CredentialManagerEntity>();
        final Iterator<Entity> iterator = pkiEntityList.iterator();
        while (iterator.hasNext()) {
            try {
                entitySet.add(PKIModelMapper.credMEndEntitySummaryFrom(iterator.next()));
            } catch (final CredentialManagerInvalidEntityException e) {
                throw new CredentialManagerInvalidArgumentException(e);
            }
        }
        return entitySet;
    }

    public Set<CredentialManagerEntityCertificates> getEntitiesCertByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInvalidEntityException, CredentialManagerInternalServiceException {
        final List<Entity> pkiEntityList = this.getPkiEntitiesByCategory(categoryName);

        Set<CredentialManagerEntityCertificates> entitySet;
        try {
            entitySet = this.listEntityToSetCredentialManagerEntityCertificates(pkiEntityList);
        } catch (final CredentialManagerCertificateEncodingException e) {
            throw new CredentialManagerInternalServiceException(e);
        }

        return entitySet;
    }

    @Override
    public boolean isOTPValid(final String entityName, final String otp)
            throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException {

        this.systemRecorder.recordCommand("isOTPValid", CommandPhase.STARTED, this.className, entityName, null);

        boolean result = false;
        try {
            result = this.getEntityManager().isOTPValid(entityName, otp);
        } catch (final OTPExpiredException e) {
            this.systemRecorder.recordError("OtpExpiredException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerOtpExpiredException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final EntityNotFoundException e) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerEntityNotFoundException("Entity : " + entityName + " - " + e.getMessage());
        } catch (final EntityServiceException e) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, entityName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + e.getMessage());
        }

        this.systemRecorder.recordCommand("isOTPValid", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityName, null);

        return result;

    }

    /**
     * @param pkiEntityList
     * @return
     * @throws CredentialManagerCertificateEncodingException
     */
    private Set<CredentialManagerEntityCertificates> listEntityToSetCredentialManagerEntityCertificates(final List<Entity> pkiEntityList)
            throws CredentialManagerInvalidEntityException, CredentialManagerCertificateEncodingException {
        // trasform the list in set
        final Set<CredentialManagerEntityCertificates> entitySet = new HashSet<CredentialManagerEntityCertificates>();
        final Iterator<Entity> iterator = pkiEntityList.iterator();
        while (iterator.hasNext()) {
            entitySet.add(PKIModelMapper.credMEndEntityCertificatesFrom(iterator.next()));
        }
        return entitySet;
    }

    private List<Entity> getPkiEntitiesByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {
        this.systemRecorder.recordCommand("getEntitiesByCategory", CommandPhase.STARTED, this.className, categoryName, null);

        List<Entity> pkiEntityList = new ArrayList<Entity>();
        final EntityCategory category = new EntityCategory();
        category.setName(categoryName);

        try {
            pkiEntityList = this.getEntityManager().getEntitiesByCategoryv1(category);
        } catch (final EntityCategoryNotFoundException e) {
            this.systemRecorder.recordError("EntityCategoryNotFoundException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidArgumentException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final EntityServiceException e) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityCategoryException e) {
            this.systemRecorder.recordError("InvalidEntityCategoryException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("InvalidEntityException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("InvalidEntityAttributeException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        }
        log.info("ProfileManagerImpl getEntitiesByCategory end");

        this.systemRecorder.recordCommand("getEntitiesCertificatesByCategory", CommandPhase.FINISHED_WITH_SUCCESS, this.className, categoryName, null);
        return pkiEntityList;
    }

    private List<Entity> getPkiEntitiesSummaryByCategory(final String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException {
        this.systemRecorder.recordCommand("getPkiEntitiesSummaryByCategory", CommandPhase.STARTED, this.className, categoryName, null);

        List<Entity> pkiEntityList = new ArrayList<Entity>();
        final EntityCategory category = new EntityCategory();
        category.setName(categoryName);

        try {
            log.info("DESPICABLE ProfileManagerImpl getPkiEntitiesSummaryByCategory start");

            pkiEntityList = this.getEntityManager().getEntitiesSummaryByCategory(category);
        } catch (final EntityCategoryNotFoundException e) {
            this.systemRecorder.recordError("EntityCategoryNotFoundException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidArgumentException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final EntityServiceException e) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInternalServiceException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityCategoryException e) {
            this.systemRecorder.recordError("InvalidEntityCategoryException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityException e) {
            this.systemRecorder.recordError("InvalidEntityException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        } catch (final InvalidEntityAttributeException e) {
            this.systemRecorder.recordError("InvalidEntityAttributeException", ErrorSeverity.ERROR, this.className, categoryName, e.getMessage());
            throw new CredentialManagerInvalidEntityException("Category : " + categoryName + " - " + e.getMessage());
        }
        log.info("DESPICABLE ProfileManagerImpl getPkiEntitiesSummaryByCategory end");

        this.systemRecorder.recordCommand("getPkiEntitiesSummaryByCategory", CommandPhase.FINISHED_WITH_SUCCESS, this.className, categoryName, null);
        return pkiEntityList;
    }

    @Override
    public void reissue(final String entityName)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        try {
            final PKIEntityFactory eeFactory = new PKIEntityFactoryImpl();
            final Entity endEntityRequest = eeFactory.setName(entityName).buildForRequest();
            this.systemRecorder.recordCommand("reissueEntity", CommandPhase.STARTED, this.className, entityName, null);

            Entity pkiEndEntity = this.getEntityManager().getEntity(endEntityRequest);

            pkiEndEntity.getEntityInfo().setStatus(EntityStatus.REISSUE);

            pkiEndEntity = this.getEntityManager().updateEntity(pkiEndEntity);

            this.systemRecorder.recordCommand("reissueEntity", CommandPhase.FINISHED_WITH_SUCCESS, this.className, entityName, null);

        } catch (final AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidEntityAttributeException | InvalidEntityCategoryException
                | InvalidProfileException | InvalidSubjectAltNameExtension | InvalidSubjectException | MissingMandatoryFieldException
                | ProfileNotFoundException | InvalidEntityException | CRLGenerationException | InvalidCRLGenerationInfoException
                | CRLExtensionException | UnsupportedCRLVersionException | EntityAlreadyExistsException ex) {
            this.systemRecorder.recordError("PKIBaseException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityServiceException ex) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInternalServiceException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final EntityNotFoundException ex) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerEntityNotFoundException("Entity : " + entityName + " - " + ex.getMessage());
        } catch (final CredentialManagerInvalidEntityException ex) {
            this.systemRecorder.recordError("CredentialManagerInvalidEntityException", ErrorSeverity.ERROR, this.className, entityName, ex.getMessage());
            throw new CredentialManagerInvalidEntityException("Entity : " + entityName + " - " + ex.getMessage());
        }
    }

    @Override
    public void reissue(final String caName, final String serialNumber)
            throws CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        try {
            final String entityName = this.getEntityManager().getEntityNameByIssuerNameAndSerialNumber(caName, serialNumber);
            this.reissue(entityName);
        } catch (final CANotFoundException ex) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, caName, ex.getMessage());
            throw new CredentialManagerCANotFoundException("CA Entity : " + caName + " - " + ex.getMessage());
        } catch (final SerialNumberNotFoundException ex) {
            this.systemRecorder.recordError("EntityNotFoundException", ErrorSeverity.ERROR, this.className, serialNumber, ex.getMessage());
            throw new CredentialManagerSNNotFoundException("Serial Number : " + serialNumber + " - " + ex.getMessage());
        } catch (final InvalidEntityException e) {
            throw new CredentialManagerInvalidEntityException("CA Entity : " + caName + " - " + e.getMessage());
        }
    }

    @Override
    public Set<CredentialManagerEntity> getServices() throws CredentialManagerInternalServiceException {
        Set<CredentialManagerEntity> entities = null;
        try {
            entities = this.getEntitiesByCategory(CategoryManagement.getServiceName());
        } catch (CredentialManagerInvalidEntityException | CredentialManagerInvalidArgumentException e) {
            throw new CredentialManagerInternalServiceException(e.getMessage());
        }
        return entities;
    }

    @Override
    public Set<CredentialManagerEntityCertificates> getServicesWithCertificates() throws CredentialManagerInternalServiceException {
        Set<CredentialManagerEntityCertificates> entities = null;
        try {
            entities = this.getEntitiesCertByCategory(CategoryManagement.getServiceName());
        } catch (CredentialManagerInvalidEntityException | CredentialManagerInvalidArgumentException e) {
            throw new CredentialManagerInternalServiceException(e.getMessage());
        }
        return entities;
    }

    @Override
    public Set<CredentialManagerEntity> getServicesByTrustCA(final String trustCAName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {

        final List<Entity> pkiEntityList = this.getEntitiesByTrustCA(trustCAName);
        Set<CredentialManagerEntity> entitySet = null;
        entitySet = this.listEntityToSetCredentialManagerEntity(pkiEntityList);
        return entitySet;
    }

    @Override
    public Set<CredentialManagerEntityCertificates> getServicesWithCertificatesByTrustCA(final String trustCAName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {

        final List<Entity> pkiEntityList = this.getEntitiesByTrustCA(trustCAName);
        Set<CredentialManagerEntityCertificates> entitySet = null;
        try {
            entitySet = this.listEntityToSetCredentialManagerEntityCertificates(pkiEntityList);
        } catch (final CredentialManagerInvalidEntityException | CredentialManagerCertificateEncodingException e) {
            throw new CredentialManagerInternalServiceException(e.getMessage());
        }

        return entitySet;
    }

    private List<Entity> getEntitiesByTrustCA(final String trustCAName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {
        try {
            this.checkCAName(trustCAName);

            final List<Entity> entitiesToReturn = new ArrayList<>();
            String categoryName;

            categoryName = CategoryManagement.getServiceName();

            //No Category is assigned to entityProfile used for service so all entityProfiles we have to get
            //final List<EntityProfile> entityProfiles = getProfilesByCategory(categoryName);
            List<EntityProfile> entityProfiles;
            entityProfiles = this.getAllEntityProfiles();
            final Set<String> entityProfileNames = new HashSet<String>();
            if (entityProfiles != null) {
                for (final EntityProfile entityProfile : entityProfiles) {
                    boolean found = false;
                    for (final TrustProfile trustProfile : entityProfile.getTrustProfiles()) {
                        for (final ExtCA extCA : trustProfile.getExternalCAs()) {
                            if (extCA.getCertificateAuthority().getName().equals(trustCAName)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            for (final TrustCAChain trustCAChain : trustProfile.getTrustCAChains()) {
                                if (trustCAChain.getInternalCA().getCertificateAuthority().getName().equals(trustCAName)) {
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found) {
                            break;
                        }
                    }
                    if (found) {
                        entityProfileNames.add(entityProfile.getName());
                    }
                }
            }

            List<Entity> pkiEntities;

            pkiEntities = this.getPkiEntitiesByCategory(categoryName);

            for (final Entity entity : pkiEntities) {
                boolean found = false;
                for (final String entityProfileName : entityProfileNames) {
                    if (entity.getEntityProfile().getName().equals(entityProfileName)) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    entitiesToReturn.add(entity);
                }
            }
            return entitiesToReturn;
        } catch (final CredentialManagerInvalidEntityException e) {
            throw new CredentialManagerCANotFoundException(e);
        } catch (final CredentialManagerInvalidProfileException e) {
            throw new CredentialManagerInternalServiceException(e);
        }
    }

    /**
     * @param trustCAName
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerCANotFoundException
     * @throws CredentialManagerInvalidEntityException
     * @throws CredentialManagerInternalServiceException
     */
    private void checkCAName(final String trustCAName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
    CredentialManagerInvalidEntityException, CredentialManagerCANotFoundException {
        if (trustCAName == null || trustCAName.isEmpty()) {
            throw new CredentialManagerInvalidArgumentException("CAEntity name is empty");
        }
        if (!this.isCAEntityPresent(trustCAName)) {
            throw new CredentialManagerCANotFoundException("CAEntity with name trustCAName doesn't exist");
        }

    }

    /*
     * UNUSED (Dead Code) private List<EntityProfile> getProfilesByCategory(final String categoryName) throws
     * CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException {
     *
     * this.systemRecorder.recordCommand("getProfilesByCategory", CommandPhase.STARTED, className, categoryName, null);
     *
     * final EntityCategory category = new EntityCategory(); category.setName(categoryName);
     *
     * List<EntityProfile> pkiEntityProfiles = null;
     *
     * try { pkiEntityProfiles = this.getProfileManager().getProfilesByCategory(category);
     *
     * } catch (final EntityCategoryNotFoundException e) { this.systemRecorder.recordError("EntityCategoryNotFoundException", ErrorSeverity.ERROR,
     * className, categoryName, e.getMessage()); throw new CredentialManagerInvalidArgumentException("Category : " + categoryName + " - " +
     * e.getMessage()); } catch (final ProfileNotFoundException e) { this.systemRecorder.recordError("ProfileNotFoundException", ErrorSeverity.ERROR,
     * className, categoryName, e.getMessage()); throw new CredentialManagerInvalidArgumentException("Category : " + categoryName + " - " +
     * e.getMessage()); } catch (final ProfileServiceException e) { this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR,
     * className, categoryName, e.getMessage()); throw new CredentialManagerInternalServiceException("Category : " + categoryName + " - " +
     * e.getMessage()); }
     *
     * this.systemRecorder.recordCommand("getProfilesByCategory", CommandPhase.FINISHED_WITH_SUCCESS, className, categoryName, null); return
     * pkiEntityProfiles;
     *
     * }
     */
    private List<EntityProfile> getAllEntityProfiles()
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidProfileException {

        this.systemRecorder.recordCommand("getAllEntityProfiles", CommandPhase.STARTED, this.className, null, null);

        List<EntityProfile> pkiEntityProfiles = null;

        try {
            pkiEntityProfiles = this.getProfileManager().getActiveProfiles(ProfileType.ENTITY_PROFILE).getEntityProfiles();

        } catch (final ProfileServiceException e) {
            this.systemRecorder.recordError("EntityServiceException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final InvalidProfileException e) {
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final InvalidProfileAttributeException e) {
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        }

        this.systemRecorder.recordCommand("getAllEntityProfiles", CommandPhase.FINISHED_WITH_SUCCESS, this.className, null, null);
        return pkiEntityProfiles;

    }

    public ProfileManagementService getProfileManager() {

        RBACManagement.injectUserName(this.ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            log.debug("Using Mock PKI ProfileManager");
            return this.mockProfileManager;
        } else {
            return this.pkiProfileManager;
        }
    }

    public EntityManagementService getEntityManager() {

        RBACManagement.injectUserName(this.ctxService);

        if (PKIMockManagement.useMockProfileManager()) {
            log.debug("Using Mock PKI EntityManager");
            return this.mockEntityManager;
        } else {
            return this.pkiEntityManager;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.api.ProfileManager#setLockProfile(java.lang.Boolean)
     */
    @Override
    public void setLockProfile(final String profileName, final CredentialManagerProfileType profileType, final Boolean lock)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException {
        AbstractProfile pkiProfile = null;

        if (profileType.equals(CredentialManagerProfileType.ENTITY_PROFILE)) {
            pkiProfile = this.getProfile(profileName, ProfileType.ENTITY_PROFILE);
        } else if (profileType.equals(CredentialManagerProfileType.CERTIFICATE_PROFILE)) {
            pkiProfile = this.getProfile(profileName, ProfileType.CERTIFICATE_PROFILE);
        }
        pkiProfile.setModifiable(lock.booleanValue());
        try {
            this.getProfileManager().updateProfile(pkiProfile);
        } catch (final CertificateExtensionException e) {
            this.systemRecorder.recordError("CertificateExtensionException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final InvalidSubjectException e) {
            this.systemRecorder.recordError("InvalidSubjectException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final MissingMandatoryFieldException e) {
            this.systemRecorder.recordError("MissingMandatoryFieldException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidArgumentException(e.getMessage());
        } catch (final UnSupportedCertificateVersion e) {
            this.systemRecorder.recordError("UnSupportedCertificateVersion", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        } catch (final AlgorithmNotFoundException e) {
            this.systemRecorder.recordError("AlgorithmNotFoundException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final CANotFoundException e) {
            this.systemRecorder.recordError("CANotFoundException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final EntityCategoryNotFoundException e) {
            this.systemRecorder.recordError("EntityCategoryNotFoundException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final InvalidCAException e) {
            this.systemRecorder.recordError("InvalidCAException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final InvalidEntityCategoryException e) {
            this.systemRecorder.recordError("InvalidEntityCategoryException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final InvalidProfileException e) {
            this.systemRecorder.recordError("InvalidProfileException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final InvalidProfileAttributeException e) {
            this.systemRecorder.recordError("InvalidProfileAttributeException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final ProfileAlreadyExistsException e) {
            this.systemRecorder.recordError("ProfileAlreadyExistsException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInvalidProfileException(e.getMessage());
        } catch (final ProfileNotFoundException e) {
            this.systemRecorder.recordError("ProfileNotFoundException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerProfileNotFoundException(e.getMessage());
        } catch (final ProfileServiceException e) {
            this.systemRecorder.recordError("ProfileServiceException", ErrorSeverity.ERROR, this.className, null, e.getMessage());
            throw new CredentialManagerInternalServiceException(e.getMessage());
        }

    }
}
