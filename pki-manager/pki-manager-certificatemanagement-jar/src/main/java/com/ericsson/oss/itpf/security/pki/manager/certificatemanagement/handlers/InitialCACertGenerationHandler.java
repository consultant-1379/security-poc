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
import java.util.Arrays;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * This class generates initial ACTIVE certificate for CA Entity. It builds required information for certificate generation and calls pki core to generate CA keys and certificates.
 */
public class InitialCACertGenerationHandler {

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
    CRLManager crlManager;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    CertificateEventNotifier certificateEventNotifier;

    /**
     * Generates certificate for the {@link CAEntity}. It does all the validations required and prepares {@link CertificateGenerationInfo} and passes to PKI Core. Then PKI core generates the CSR for
     * the CA and generates certificate for that CA. The newly generated certificate will automatically be published to TDPS.
     * 
     * @param caEntityName
     *            The CA entity name.
     * @return The Certificate object.
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
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public Certificate generateCertificate(final String entityName) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        try {
            final CAEntity caEntity = entityHelper.getCAEntity(entityName);
            // do the validations
            if (caEntity.getEntityProfile().getCertificateProfile().getIssuer() != null) {
                certificateValidator.validateIssuerChain(caEntity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());
            }

            final Algorithm keyGenerationAlgorithm = entityHelper.getOverridenKeyGenerationAlgorithm(caEntity);
            caEntity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
            // TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
            SubjectUtils.removeDNQFromSubject(caEntity.getCertificateAuthority().getSubject());
            final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoBuilder.build(caEntity, RequestType.NEW);
            caPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);

            final Certificate certificate = invokePKICoreGenerateCertificate(certificateGenerationInfo);
            caPersistenceHelper.storeCertificate(caEntity.getCertificateAuthority().getName(), certificateGenerationInfo, certificate);

            if (caEntity.isPublishCertificatetoTDPS()) {
                certificateEventNotifier.notify(EntityType.CA_ENTITY, caEntity.getCertificateAuthority().getName(), TDPSPublishStatusType.PUBLISH, Arrays.asList(certificate));
            }

            if (!ValidationUtils.isNullOrEmpty(caEntity.getCertificateAuthority().getCrlGenerationInfo())) {
                final CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier(caEntity.getCertificateAuthority().getName(), certificate.getSerialNumber());
                crlManager.generateCRL(caCertIdentifier);
                systemRecorder.recordSecurityEvent("Certificate Management Service", "InitialCACertGeneration", "CA Entity for which CRL generated is : " + entityName,
                        "CAEntityCertificateGenetation", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            } else {
                systemRecorder.recordSecurityEvent("Certificate Management Service", "InitialCACertGeneration", "CRL Generated Failed for CA Entity " + entityName
                        + " as CA does not have CRL generation Information" + entityName, "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            }
            return certificate;

        } catch (CAEntityNotInternalException exception) {
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND, exception.getMessage());
            throw new CANotFoundException(exception);
        } catch (CertificateException | IOException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception.getMessage());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + exception);
        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
    }

    private Certificate invokePKICoreGenerateCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmNotFoundException, CANotFoundException,
            CertificateGenerationException, CertificateServiceException, InvalidCertificateRequestException {

        try {
            return certificatemanagementEserviceProxy.getCoreCertificateManagementService().createCertificate(certificateGenerationInfo);

        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException certificateGenerationException) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, certificateGenerationException.getMessage());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + " : " + certificateGenerationException.getMessage());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException validationException) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, validationException.getMessage());
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + " : " + validationException.getMessage(), validationException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException certifiateReqException) {
            logger.error(ErrorMessages.INVALID_CSR, certifiateReqException.getMessage());
            throw new InvalidCertificateRequestException(ErrorMessages.INVALID_CSR + " : " + certifiateReqException.getMessage(), certifiateReqException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.ENTITY_NOT_FOUND + " : " + entityNotFoundException.getMessage(), entityNotFoundException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException unsupportedCertificateVersionException) {
            logger.error(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unsupportedCertificateVersionException.getMessage());
            throw new CertificateGenerationException(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION + " : " + unsupportedCertificateVersionException.getMessage(),
                    unsupportedCertificateVersionException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + " : " + exception.getMessage(), exception);
        }

    }
}