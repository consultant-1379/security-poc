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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.api;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 * This is an interface for Revocation Service. It provides below Revocation operations.
 * <ul>
 * <li>Revokes a particular Certificate based on RevocationRequest</li>
 * </ul>
 */
@EService
@Remote
public interface RevocationService {

    /**
     * This API method is used to revoke Certificates that are present in RevocationRequest
     *
     * @param revocationRequest
     *            RevocationRequest contains the details of the certificate revocation request.
     * @throws CertificateExpiredException
     *             thrown when the revocation request is received for an expired certificate.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate in RevocationRequest not present.
     * @throws CertificatePathValidationException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws CertificateRevokedException
     *             thrown when the revocation request is received for a revoked certificate.
     * @throws CoreEntityNotFoundException
     *             thrown when the given CAEntity or Entity is not present.
     * @throws RootCARevocationException
     *             thrown when Revocation Request is received for the Root CA to indicate that Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    void revokeCertificate(final RevocationRequest revocationRequest) throws CertificateNotFoundException, CertificateExpiredException, CertificatePathValidationException,
            CertificateRevokedException, CoreEntityNotFoundException, RootCARevocationException, RevocationServiceException;
}
