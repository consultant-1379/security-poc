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

import java.io.IOException;

import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

/**
 * This class does the renew operation for the CA Entity. It builds required information for certificate generation and calls pki core to generate certificate.
 */
public class CARenewHandler {

    @Inject
    CertificateValidator certificateValidator;

    @Inject
    EntityHelper entityHelper;

    @Inject
    CertificateGenerationInfoBuilder certificateGenerationInfoBuilder;

    @Inject
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    CAHierarchyPersistenceHandler caHierarchyPersistenceHandler;

    @Inject
    EntitiesModelMapperFactory modelMapperFactory;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    CRLManager crlManager;

    @Inject
    CertificateEventNotifier certificateEventNotifier;

    /**
     * Renew certificate for the {@link CAEntity}. It does all the validations required and prepares {@link CertificateGenerationInfo} and passes to PKI Core. Then PKI core generates the CSR for the
     * CA and generates certificate for that CA. The newly generated certificate will automatically be published to TDPS.
     *
     * @param caEntity
     *            The CA entity object.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate of the given entity is revoked.
     */
    public void renewCertificate(final CAEntity caEntity, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        if (reIssueType == ReIssueType.CA) {
            final Certificate certificate = renewCACertificate(caEntity);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CARenewHandler", "CA certificate renewed for " + caEntity.getCertificateAuthority().getName() + "with serial number "
                    + certificate.getSerialNumber(), "CERTIFICATEMANAGEMENT.RENEW_CA_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } else if (reIssueType == ReIssueType.CA_WITH_IMMEDIATE_SUB_CAS) {
            renewCAAndSubCAsCertificate(caEntity);
        } else if (reIssueType == ReIssueType.CA_WITH_ALL_CHILD_CAS) {
            renewCAAndHierarchy(caEntity);
        } else {
            logger.error("{} Re issue type is not supported ", ErrorMessages.UNSUPPORTED_REISSUE_TYPE);
            throw new CertificateGenerationException(ErrorMessages.UNSUPPORTED_REISSUE_TYPE);
        }
    }

    private Certificate renewCACertificate(final CAEntity caEntity) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        try {
            // Verify CA has active certificate to renew.
            certificateValidator.verifyEntityStatusForReissue(caEntity);
            // Verify issuer has active certificate or not
            certificateValidator.verifyCAActiveCertificatesForRenew(caEntity);

            if (caEntity.getEntityProfile().getCertificateProfile().getIssuer() != null) {
                certificateValidator.validateIssuerChain(caEntity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());
            }
            final Algorithm keyGenerationAlgorithm = entityHelper.getOverridenKeyGenerationAlgorithm(caEntity);
            caEntity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
            // TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
            SubjectUtils.removeDNQFromSubject(caEntity.getCertificateAuthority().getSubject());
            final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoBuilder.build(caEntity, RequestType.RENEW);
            caPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);

            final Certificate certificate = certificatemanagementEserviceProxy.getCoreCertificateManagementService().renewCertificate(certificateGenerationInfo);
            caPersistenceHelper.storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

            if (caEntity.isPublishCertificatetoTDPS()) {
                certificateEventNotifier.notify(EntityType.CA_ENTITY, caEntity.getCertificateAuthority().getName(), TDPSPublishStatusType.PUBLISH, Arrays.asList(certificate));
            }

            if (!ValidationUtils.isNullOrEmpty(caEntity.getCertificateAuthority().getCrlGenerationInfo())) {
                final CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier(caEntity.getCertificateAuthority().getName(), certificate.getSerialNumber());
                crlManager.generateCRL(caCertIdentifier);
                systemRecorder.recordSecurityEvent("PKIManager.CertificateManagement", "CARenewHandler", "CRL generated for CA " + caEntity.getCertificateAuthority().getName()
                        + " with serial number " + certificate.getSerialNumber(), "CERTIFICATEMANAGEMENT.GENERATE_CA_CRL", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            } else {
                systemRecorder.recordSecurityEvent("PKIManager.CertificateManagement", "CARenewHandler", "CRL generation failed for CA " + caEntity.getCertificateAuthority().getName()
                        + "  with serial number " + certificate.getSerialNumber() + " because CA deos not have CRL generation info", "CERTIFICATEMANAGEMENT.GENERATE_CA_CRL",
                        ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }

            return certificate;

        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception.getMessage());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + ":" + exception.getMessage());
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.ENTITY_NOT_FOUND + entityNotFoundException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException validationException) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, validationException.getMessage());
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + validationException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException unSupportedCertificateVersion) {
            logger.error(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unSupportedCertificateVersion.getMessage());
            throw new CertificateGenerationException(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION + unSupportedCertificateVersion);
        } catch (final CertificateException | IOException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception.getMessage());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + exception);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(" Unable to find the CA ");
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException.getMessage(), entityNotFoundException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException | PersistenceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        }

    }

    private void renewCAAndSubCAsCertificate(final CAEntity caEntity) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        // Do the renew operation for the requested CA.
        renewCACertificate(caEntity);

        // Then get the Sub CAs of that CA and perform renew for each Sub CA.
        try {
            final List<CAEntityData> childCAs = caHierarchyPersistenceHandler.getSubCAEntities(caPersistenceHelper.getCAEntity(caEntity.getCertificateAuthority().getName()));
            for (final CAEntityData caEntityData : childCAs) {
                final CAEntity subCA = (CAEntity) modelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY).toAPIFromModel(caEntityData);
                renewCACertificate(subCA);
            }
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CARenewHandler", "CA and its Sub CAs : " + getListOfSubCANames(childCAs) + " certificates are renewed ",
                    "CERTIFICATEMANAGEMENT.RENEW_CA_AND_SUBCAS_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final EntityServiceException entityServiceException) {
            logger.error(ErrorMessages.ERROR_GETTING_SUBCAS, entityServiceException.getMessage());
            throw new CertificateServiceException(" Error occurred while getting the Sub CAs of a CA Entity :: {} " + caEntity.getCertificateAuthority().getName(), entityServiceException);
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(" Error occurred while renewing certificates for the CA and Sub CAs :: {} " + caEntity.getCertificateAuthority().getName(), persistenceException);
        }
    }

    private void renewCAAndHierarchy(final CAEntity caEntity) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        // Do the renew for the requested CA.
        renewCACertificate(caEntity);

        try {
            // Then get all the CAs in its hierarchy and perform the renew operation.
            final TreeNode<CAEntity> caHierarchy = caHierarchyPersistenceHandler.getCAHierarchyByName(caEntity.getCertificateAuthority().getName());
            renewChildCAs(caHierarchy);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CARenewHandler", "CA " + caEntity.getCertificateAuthority().getName()
                    + " and its hierarchy certificates are renewed ", "CERTIFICATEMANAGEMENT.RENEW_CA_AND_HIERARCHY", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final EntityServiceException entityServiceException) {
            logger.error(" Unable to get hierarchy for the CA {}", caEntity.getCertificateAuthority().getName());
            throw new CertificateServiceException(ErrorMessages.UNABLE_TO_GET_CA_HIERARCHY + entityServiceException.getMessage(), entityServiceException);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(" Unable to find the CA ");
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException.getMessage(), entityNotFoundException);
        }
    }

    private void renewChildCAs(final TreeNode<CAEntity> caHierarchy) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityAttributeException, InvalidEntityAttributeException, RevokedCertificateException {

        final List<TreeNode<CAEntity>> childCAs = caHierarchy.getChilds();
        for (final TreeNode<CAEntity> childCA : childCAs) {
            renewCACertificate(childCA.getData());
            if (!childCA.getChilds().isEmpty()) {
                renewChildCAs(childCA);
            }
        }
    }

    private List<String> getListOfSubCANames(final List<CAEntityData> caEntities) {

        final List<String> listOfSubCAs = new ArrayList<String>();
        for (final CAEntityData caEntityData : caEntities) {
            listOfSubCAs.add(caEntityData.getCertificateAuthorityData().getName());
        }

        return listOfSubCAs;
    }
}