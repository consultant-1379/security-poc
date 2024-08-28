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

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateChainHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This abstract class contains common methods that are used by CAEntity and Entity CertificateManager.This class is extended by CAEntity and Entity CertificateManager.
 */
public abstract class AbstractCertificateManager {

    @Inject
    CertificateChainHelper certificateChainHelper;

    @Inject
    Logger logger;

    /**
     * Retrieve list of certificate chains for CAEntity and Entity.
     * 
     * @param entityName
     *            The entity name
     * @param entityType
     *            entity type
     * @param isInactiveValid
     *            boolean value which specifies whether an Inactive certificate is valid for the chain building or not.
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certificateChains Return list of complete Chain of certificates.
     * 
     * @throws CertificateServiceException
     *             Thrown in case of PersistenceException,CertificateException,IOException.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidCertificateStatusException
     *             Thrown when the Certificate Status is invalid to get the Certificate Chain.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not found or doesn't have any valid certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown in case the given Entity has invalid attribute.
     */
    public List<CertificateChain> getCertificateChain(final String entityName, final EntityType entityType, final boolean isInactiveValid, final CertificateStatus... certificateStatus)
            throws CertificateServiceException,
            InvalidCAException, InvalidCertificateStatusException, InvalidEntityException, InvalidEntityAttributeException {

        final CertificateStatus[] certificateStatuslist = validateAndGetCertificateStatus(certificateStatus);
        final List<CertificateChain> certificateChains = certificateChainHelper.getCertificateChainList(entityName, entityType, isInactiveValid, certificateStatuslist);
        return certificateChains;

    }

    /**
     * Returns complete chain of active and inactive certificates of CAEntity.
     *
     * @param entityName
     *            The entity name
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certificates Returns complete chain of active and inactive certificates of CAEntity.
     *
     * @throws CertificateServiceException
     *             Thrown in case of PersistenceException,CertificateException,IOException.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityAttributeException
     *             Thrown in case the given entity has invalid attribute.
     */
    public List<Certificate> getCertificateChain(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException, InvalidCAException,
            InvalidEntityAttributeException {

        return certificateChainHelper.getCertificateChain(entityName, EntityType.CA_ENTITY, certificateStatus);

    }

    private CertificateStatus[] validateAndGetCertificateStatus(CertificateStatus... certificateStatus) throws InvalidCertificateStatusException {

        if (certificateStatus == null || certificateStatus.length == 0) {

            certificateStatus = new CertificateStatus[2];
            certificateStatus[0] = CertificateStatus.ACTIVE;
            certificateStatus[1] = CertificateStatus.INACTIVE;
            return certificateStatus;
        }

        final CertificateStatus[] certificateStatuslist = removeDuplicates(certificateStatus);

        for (final CertificateStatus certStatus : certificateStatuslist) {
            if (!supportedCertificateStatusForChain(certStatus)) {
                throw new InvalidCertificateStatusException(ErrorMessages.CHAIN_NOT_SUPPORTED);
            }
        }
        return certificateStatuslist;

    }

    private CertificateStatus[] removeDuplicates(final CertificateStatus... certificateStatus) {

        final Set<CertificateStatus> certificateStatusWithoutDuplicates = new LinkedHashSet<CertificateStatus>(Arrays.asList(certificateStatus));
        return (CertificateStatus[]) certificateStatusWithoutDuplicates.toArray(new CertificateStatus[certificateStatusWithoutDuplicates.size()]);

    }

    private boolean supportedCertificateStatusForChain(final CertificateStatus certificateStatus) {

        switch (certificateStatus) {
        case ACTIVE:
        case INACTIVE:
            return true;
        case EXPIRED:
        case REVOKED:
            return false;
        default:
            throw new IllegalArgumentException(ErrorMessages.INVALID_CERTIFICATE_STATUS);
        }
    }

}
