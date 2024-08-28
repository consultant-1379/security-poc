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
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * This class provides interfaces to fetch Certificate,CertificateChain,TrustCertificates and list of entity certificates.and this class is local to only CMP Event handler
 *
 * @author tcsramc
 *
 */
@EService
@Local
public interface CertificateManagementLocalService {
    /**
     * This method is used to generate new certificate to the given entity.
     *
     * @param entityName
     *            to which certificate has to be generated.
     * @param certificateRequest
     *            Contains information required to generate certificate.
     * @return UserCertificate.
     * @throws IOException
     *             is thrown if any I/O Error occurs.
     */
    Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException;

    /**
     * This method is used to get certificate chain till rootCA for the given entity.
     *
     * @param entityName
     *            to which chain has to be fetched.
     * @return certificate chain
     */
    CertificateChain getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityException,
            InvalidEntityAttributeException;

    /**
     * This method is used to get trust certificates for the given entity.
     *
     * @param entityName
     *            to which trust certificates has to be fetched.
     * @return list of trustCertificates.
     */
    List<Certificate> getTrustCertificates(final String entityName) throws CertificateServiceException, EntityNotFoundException, ExternalCredentialMgmtServiceException, InvalidCAException,
            InvalidEntityAttributeException, ProfileNotFoundException;

    /**
     * This method is used to fetch list of entity certificates based on the given status.
     *
     * @param entityName
     *            for which certificates has to be fetched.
     * @return list of entity certificates.
     * @throws CertificateException
     *             is thrown if any error occurs while generating certificate.
     * @throws PersistenceException
     *             is thrown if any error occurs while querying to db.
     * @throws IOException
     *             is thrown if any I/O Error occurs.
     */
    List<Certificate> getEntityCertificates(final String entityName) throws CertificateNotFoundException, CertificateServiceException, EntityNotFoundException, InvalidEntityAttributeException;

    /**
     * This method is used to validate the certificate Chain of the X509Certificate
     *
     * @param certificate
     *            X509Certificate for which certificate need to be validated
     */
    void validateCertificateChain(final X509Certificate certificate) throws CertificateServiceException, CertificateNotFoundException, ExpiredCertificateException, RevokedCertificateException;

}
