/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers.ImportCertificateHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;

public class ImportCertificateManager {

    @Inject
    Logger logger;

    @Inject
    ImportCertificateHandler importCertificateHandler;

    /**
     * This method is used for handling the import certificate request for the certificate signed by external root ca
     * 
     * @param caName
     *            name of the CA entity for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            flag to enable RFC validations on the provided certificate
     * @param caReIssueType
     *            type that specifies re issue need to be done for Sub CAs of Root CA
     * @throws AlgorithmNotFoundException
     *             This exception is thrown if the given algorithm is not supported/not present in the database ,in case of CertificateImport/ CertificateGeneration for Re-issue of child CA's of
     *             imported CA
     * @throws CANotFoundException
     *             This exception is thrown if the given CA is not present in the database
     * @throws CertificateGenerationException
     *             This exception is thrown to indicate that an exception has occurred during certificate generation during Re-issue of child CA's of imported CA
     * @throws CertificateNotFoundException
     *             This exception is thrown when CA does not have Active Certificate to revoke during Re-issue of child CA's of imported CA
     * @throws CertificateServiceException
     *             This exception is thrown to indicate any internal database errors or any unconditional exceptions during Root CA certificate import signed by external CA and also during Re-issue of
     *             child CA's of imported CA
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain is expired.
     * @throws InvalidCAException
     *             This exception is thrown when the given CA is not having a valid state during certificate import
     * @throws IssuerCertificateRevokedException
     *             This exception is thrown if the Issuer certificate is already revoked during Re-issue of child CA's of imported CA
     * @throws InvalidEntityException
     *             This exception is thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             This exception is thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void importCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException,
            CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException,
            IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException,
            RootCertificateRevocationException, RevocationServiceException {
        logger.debug("Importing the certificate signed by external CA for the root CA {} ", caName);

        importCertificateHandler.importCertificate(caName, x509Certificate, enableRFCValidation, caReIssueType);

        logger.debug("Imported the certificate signed by external CA for the root CA {} ", caName);
    }

}
