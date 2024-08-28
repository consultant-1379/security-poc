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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.modelmapper.RevocationRequestModelMapper;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.validator.RevocationRequestValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.revocation.helper.RevocationPersistenceHelper;

/**
 * This class is used to perform Revocation operations.
 * 
 * @author xvambur
 * 
 */
public class RevocationManager {

    @Inject
    Logger logger;

    @Inject
    RevocationPersistenceHelper revocationPersistenceHelper;

    @Inject
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Inject
    RevocationRequestValidator revocationRequestValidator;

    /**
     * This method is used to revoke the given list of certificates for a particular Entity/CAEntity.
     * 
     * @param revocationRequest
     *            RevocationRequestData object which contains the details regarding the revocation request like CAEntity,Entity, RevocationReason etc
     * @throws CertificateNotFoundException
     *             thrown when the certificates for which the revocation request is raised is not found.
     * @throws CertificateExpiredException
     *             thrown when the certificate status is expired.
     * @throws CertificatePathValidationException
     *             thrown to indicate Issuer of the given Entity Certificate is already revoked.
     * @throws CertificateRevokedException
     *             thrown when revocation operation is requested for a revoked certificate.
     * @throws CoreEntityNotFoundException
     *             thrown when the entity for whose certificates the revocation request is raised is not found
     * @throws RootCARevocationException
     *             thrown to indicate Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors or any unconditional exceptions.
     */
    public void revokeCertificateByRevocationRequest(final RevocationRequest revocationRequest) throws CertificateNotFoundException, CertificateExpiredException, CertificatePathValidationException,
            CertificateRevokedException, CoreEntityNotFoundException, RootCARevocationException, RevocationServiceException {
        final RevocationRequestData revocationRequestData = revocationRequestModelMapper.fromAPIModel(revocationRequest);
        revocationRequestData.setStatus(RevocationRequestStatus.NEW);
        revocationRequestValidator.validate(revocationRequestData);
        revocationPersistenceHelper.storeRevocationRequest(revocationRequestData);
        revokeCertificates(revocationRequestData);
        revocationPersistenceHelper.updateRevocationRequestStatus(revocationRequestData, RevocationRequestStatus.REVOKED);
    }

    /**
     * This method is used to update the certificates' status as revoked for which the revocation request is raised.
     * 
     * @param revocationRequestData
     *            RevocationRequestData object which contains the details regarding the revocation request like CAEntity,Entity, RevocationReason etc
     * @throws RevocationServiceException
     *             thrown when there occurs any internal errors while processing the revocation request.
     */
    private void revokeCertificates(final RevocationRequestData revocationRequestData) throws RevocationServiceException {
        revocationPersistenceHelper.updateCertificateStatusForRevocationRequest(revocationRequestData);
    }
}
