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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateChainBuilder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

public class CertificateChainHelper {

    @Inject
    Logger logger;

    @Inject
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    EntityHelper entityHelper;

    /**
     * Returns complete chain of active and/or inactive certificates based on certificateStatus
     * 
     * @param entityName
     *            The entity name
     * @param entityType
     *            entity type.
     * @param isInactiveValid
     *            boolean value which specifies whether an Inactive certificate is valid for the chain building or not.
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certificateChains Return certificateChains from entity to RootCA
     * @throws CertificateServiceException
     *             Thrown in case of PersistenceException,CertificateException,IOException
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not found or doesn't have any valid certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown in case the given Entity has invalid attribute.
     */
    public List<CertificateChain> getCertificateChainList(final String entityName, final EntityType entityType, final boolean isInactiveValid, final CertificateStatus... certificateStatus)
            throws CertificateServiceException,
            InvalidCAException, InvalidEntityException, InvalidEntityAttributeException {

        try {

            final List<Certificate> certificates = getCertificates(entityName, entityType, certificateStatus);
            final List<CertificateChain> certificateChains = new ArrayList<>();
            for (final Certificate certificate : certificates) {
                final List<Certificate> singleCertificateChain = certificatePersistenceHelper.getCertificateChain(certificate, isInactiveValid);
                if (singleCertificateChain != null) {
                    final CertificateChain certificateChain = new CertificateChainBuilder().certificates(singleCertificateChain).build();
                    certificateChains.add(certificateChain);
                }
            }

            if (!certificates.isEmpty() && certificateChains.isEmpty()) {
                logger.error("No valid Certificate chain for the CA : {}", entityName);

                throw new InvalidCAException(ErrorMessages.NO_VALID_CERTIFICATE_CHAIN_FOR_CA + " " + entityName);
            }

            return certificateChains;

        } catch (CertificateException | IOException exception) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, exception.getMessage());
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR, exception);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception Occured while retrieving certificate chain : {}", persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }

    }

    /**
     * Returns complete chain of active and inactive certificates of CAEntity.
     *
     * @param entityName
     *            The entity name
     * @param entityType
     *            entity type.
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certList Return list of active and inactive chain from entity to RootCA
     *
     * @throws CertificateServiceException
     *             Thrown in case of PersistenceException,CertificateException,IOException
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not found or doesn't have any valid certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    public List<Certificate> getCertificateChain(final String entityName, final EntityType entityType, final CertificateStatus... certificateStatus) throws CertificateServiceException,
            InvalidCAException, InvalidEntityAttributeException {

        try {

            final List<Certificate> certificates = getCertificates(entityName, entityType, certificateStatus);
            final Set<Certificate> certificateChains = new LinkedHashSet<>();

            for (final Certificate certificate : certificates) {
                final List<Certificate> singleCertificateChain = certificatePersistenceHelper.getCertificateChain(certificate, Constants.INACTIVE_CERTIFICATE_VALID);
                if (singleCertificateChain != null) {
                    certificateChains.addAll(singleCertificateChain);
                }
            }

            if (!certificates.isEmpty() && certificateChains.isEmpty()) {
                logger.error("No valid Certificate chain found for the CA", entityName);

                throw new InvalidCAException(ErrorMessages.NO_VALID_CERTIFICATE_CHAIN_FOR_CA + " " + entityName);
            }

            return new ArrayList<>(certificateChains);

        } catch (CertificateException | IOException exception) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, exception.getMessage());
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR, exception);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception Occured while retrieving certificate chain : {}", persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }

    }

    private List<Certificate> getCertificates(final String entityName, final EntityType entityType, final CertificateStatus... certificateStatus) throws CertificateException,
            InvalidCAException, InvalidEntityException, IOException {

        List<Certificate> certificates = null;

        if (entityType.equals(EntityType.CA_ENTITY)) {
            certificates = getCAEntityCertificates(entityName, certificateStatus);

        } else {
            certificates = getEntityCertificates(entityName, certificateStatus);
        }
        return certificates;

    }

    private List<Certificate> getEntityCertificates(final String entityName, final CertificateStatus... certificateStatus) throws CertificateException, InvalidEntityException, IOException {

        final List<Certificate> certificates = entityPersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_0, certificateStatus);

        if (ValidationUtils.isNullOrEmpty(certificates)) {
            final String errorMessage = String.format("%s is not found or doesn't have %s certificates", entityName, Arrays.asList(certificateStatus));
            logger.error(errorMessage);
            throw new InvalidEntityException(errorMessage);

        }
        return certificates;
    }

    private List<Certificate> getCAEntityCertificates(final String entityName, final CertificateStatus... certificateStatus) throws CertificateException, InvalidCAException, IOException {

        final List<Certificate> certificates = caPersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_0, certificateStatus);

        if (ValidationUtils.isNullOrEmpty(certificates)) {
            final String errorMessage = String.format("%s is not found or doesn't have %s certificates", entityName, Arrays.asList(certificateStatus));
            logger.error(errorMessage);
            throw new InvalidCAException(errorMessage);
        }

        return certificates;
    }

}
