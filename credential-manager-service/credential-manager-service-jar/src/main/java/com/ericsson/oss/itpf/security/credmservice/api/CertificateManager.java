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
package com.ericsson.oss.itpf.security.credmservice.api;

import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@Local
public interface CertificateManager {

    CredentialManagerX509Certificate[] getCertificate(final CredentialManagerPKCS10CertRequest csr, String entityName, boolean certificateChain,
                                                      final String otp)
            throws CredentialManagerCertificateEncodingException, CredentialManagerEntityNotFoundException,
            CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException, CredentialManagerInvalidEntityException,
            CredentialManagerCertificateExsitsException;

    /**
     * @param caName
     * @param isExternal
     * @return
     * @throws CredentialManagerCertificateNotFoundException
     * @throws CredentialManagerServiceException
     */
    CredentialManagerCertificateAuthority getTrustCertificates(CredentialManagerTrustCA caName, boolean isExternal)
            throws CredentialManagerInvalidArgumentException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException, CredentialManagerInternalServiceException;

    /**
     * getCrl
     *
     * @param caName
     * @param isChainRequired
     * @param isExternal
     * @return
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerCRLServiceException
     * @throws CredentialManagerCRLEncodingException
     */
    Map<String, CredentialManagerX509CRL> getCrl(final String caName, boolean isChainRequired, boolean isExternal)
            throws CredentialManagerCRLServiceException, CredentialManagerCertificateServiceException, CredentialManagerCRLEncodingException;

    /**
     * RevokeCertificateByEntity
     *
     * @param entityName
     * @param entityType
     * @param revocationReason
     * @param invalidityDate
     * @throws CredentialManagerEntityNotFoundException
     * @throws CredentialManagerCertificateServiceException
     */
    void RevokeCertificateByEntity(final String entityName, final CredentialManagerRevocationReason revocationReason, final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException;

    /**
     * RevokeCertificateById
     *
     * @param credMCertificateIdentifier
     * @param revocationReason
     * @param invalidityDate
     * @throws CredentialManagerCertificateNotFoundException
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerExpiredCertificateException
     * @throws CredentialManagerAlreadyRevokedCertificateException
     */
    void RevokeCertificateById(final CredentialManagerCertificateIdentifier credMCertificateIdentifier,
                               final CredentialManagerRevocationReason revocationReason, final Date invalidityDate)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerExpiredCertificateException, CredentialManagerAlreadyRevokedCertificateException;

    /**
     * ListCertificates
     *
     * @param entityName
     * @param credMCertStatus
     * @param entityType
     * @throws CredentialManagerCertificateNotFoundException
     * @throws CredentialManagerCertificateServiceException
     * @throws CredentialManagerEntityNotFoundException
     * @throws CredentialManagerCertificateEncodingException
     * @throw CredentialManagerInvalidArgumentException
     */

    List<CredentialManagerX509Certificate> ListCertificates(final String entityName, final CredentialManagerEntityType entityType,
                                                            final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException;

    /**
     * printCommandOnRecorder
     *
     * @param message
     * @param category
     * @param source
     * @param entityName
     * @param infos
     */
    void printCommandOnRecorder(final String message, final CommandPhase category, final String source, final String entityName, final String infos);

    /**
     * printErrorOnRecorder
     *
     * @param message
     * @param category
     * @param source
     * @param entityName
     * @param infos
     */
    void printErrorOnRecorder(final String message, final ErrorSeverity category, final String source, final String entityName, final String infos);

    /**
     * listCertificatesSummary
     *
     * @param entityName
     * @param entityType
     * @param credMCertStatus
     */
    public List<CredentialManagerX500CertificateSummary> listCertificatesSummary(final String entityName,
                                                                                 final CredentialManagerEntityType entityType,
                                                                                 final CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerCertificateServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidArgumentException, CredentialManagerCertificateEncodingException;

}
