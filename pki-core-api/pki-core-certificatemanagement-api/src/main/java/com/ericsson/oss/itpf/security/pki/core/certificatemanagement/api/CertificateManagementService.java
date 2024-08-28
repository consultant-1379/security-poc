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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api;

import java.security.cert.X509Certificate;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 *
 * This Interface provides Certificate Management Service from PKI Core. The methods include Create, Update and Delete operations for Entity, CAEntity.
 *
 * @author xrajaba
 * @since 07/05/2015
 */
@EService
@Remote
public interface CertificateManagementService {

    // TODO : Define Exception hierarchy in PKI core. User story ref : TORF-85211

    /**
     * This method is used to create certificate for both Entity and CA entity.
     *
     * @param certificateGenerationInfo
     *            Certificate is generated using {@link CertificateGenerationInfo} object passed from PKI-Manager
     * @return Certificate object generated
     *
     * @throws AlgorithmValidationException
     *             is thrown when Algorithm validation has failed
     * @throws CertificateGenerationException
     *             in case of any issues during certificate generation
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     * @throws InvalidCertificateRequestException
     *             in case of any issues with CSR in {@link CertificateGenerationInfo}
     * @throws UnsupportedCertificateVersionException
     *             in case the provided Certificate version is not supported
     */
    Certificate createCertificate(CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException;

    /**
     * This method renews certificate for one or more number of Entities or CA Entities.
     *
     * @param certificateGenerationInfo
     *            Map with of {@link CertificateGenerationInfo} objects passed to generate certificates.
     * @return map containing entity name as key and corresponding Certificate generated as value.
     * @throws AlgorithmValidationException
     *             thrown when Algorithm validation has failed.
     * @throws CertificateGenerationException
     *             in case of any issues during certificate generation
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     * @throws InvalidCertificateRequestException
     *             in case of any issues with CSR in {@link CertificateGenerationInfo}
     * @throws UnsupportedCertificateVersionException
     *             in case the provided Certificate version is not supported
     */
    Certificate renewCertificate(CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException;

    /**
     * This method re generates keys and certificate for one or more number of CA Entities.
     *
     * @param certificateGenerationInfo
     *            list of {@link CertificateGenerationInfo} objects passed to generate certificates.
     * @return map containing entity name as key and corresponding Certificate generated as value.
     * @throws AlgorithmValidationException
     *             in case a validation exception occurs
     * @throws CertificateGenerationException
     *             in case of any issues during certificate generation
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     * @throws InvalidCertificateRequestException
     *             in case of any issues with CSR in {@link CertificateGenerationInfo}
     * @throws UnsupportedCertificateVersionException
     *             in case the provided Certificate version is not supported
     */
    Certificate reKeyCertificate(CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException;

    /**
     * This method will update certificate status to EXPIRED for all the certificates whose validity has expired.
     *
     * @throws CertificateStateChangeException
     *             This exception is thrown when CertificateStatus update has failed.
     */
    void updateCertificateStatusToExpired() throws CertificateStateChangeException;

    /**
     * Generates and returns CSR for given certificate generation info which has all parameters required such as subject, attributes required in CSR.
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} object which gives info to generate and export CSR.
     * @return {@link PKCS10CertificationRequestHolder} object which contains CSR bytes.
     * @throws AlgorithmValidationException
     *             thrown when Algorithm validation has failed.
     * @throws CertificateRequestGenerationException
     *             in case of CSR generation failed for CA Entity.
     * @throws CertificateServiceException
     *             thrown for any certificate related database errors in PKI Core.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     */
    PKCS10CertificationRequestHolder generateCSR(CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateRequestGenerationException,
            CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException;

    /**
     * Imports given certificate in the system for the CA specified.
     *
     * @param caName
     *            name of the CA.
     * @param x509Certificate
     *            certificate to be imported.
     *
     * @throws CertificateServiceException
     *             Thrown in case any failure occurred when importing certificate.
     * @throws CoreEntityNotFoundException
     *             Thrown in case given CA does not exist in the database.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     * @throws InvalidCAException
     *             This exception is thrown when the given CAEntity is not valid.
     * @throws InvalidCertificateException
     *             Thrown when Invalid certificate is found for entity
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     */
    void importCertificate(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException, InvalidCAException,
            InvalidCertificateException, InvalidOperationException;
}