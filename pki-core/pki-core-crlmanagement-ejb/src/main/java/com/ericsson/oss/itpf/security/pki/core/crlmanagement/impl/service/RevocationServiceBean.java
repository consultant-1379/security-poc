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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.service;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 * This class implements {@link RevocationService}
 * 
 */
@Profiled
@Stateless
public class RevocationServiceBean implements RevocationService {

    @Inject
    Logger logger;

    @Inject
    RevocationManager certificateRevocationManager;

    /**
     * This method is used to revoke the given list of certificates for a particular Entity/CAEntity.
     * 
     * @param revocationRequest
     *            RevocationRequestData object which contains the details regarding the revocation request like CAEntity,Entity, RevocationReason etc
     * 
     * @throws CertificateExpiredException
     *             thrown when revocation operation is requested for a expired certificate.
     * @throws CertificateNotFoundException
     *             thrown when the certificates for which the revocation request is raised is not found.
     * @throws CertificateRevokedException
     *             thrown when revocation operation is requested for a revoked certificate.
     * @throws CertificatePathValidationException
     *             thrown to indicate Issuer of the given Entity Certificate is already revoked.
     * @throws CoreEntityNotFoundException
     *             thrown when the entity for whose certificates the revocation request is raised is not found
     * @throws RootCARevocationException
     *             thrown to indicate Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors or any unconditional exceptions.
     * 
     * 
     * 
     */
    @Override
    public void revokeCertificate(final RevocationRequest revocationRequest) throws CertificateNotFoundException, CertificateExpiredException, CertificatePathValidationException,
            CertificateRevokedException, CoreEntityNotFoundException, RootCARevocationException, RevocationServiceException {
        certificateRevocationManager.revokeCertificateByRevocationRequest(revocationRequest);

    }
}
