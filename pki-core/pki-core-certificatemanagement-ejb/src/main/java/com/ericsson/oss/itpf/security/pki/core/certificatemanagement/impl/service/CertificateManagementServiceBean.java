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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl.service;

import java.security.cert.X509Certificate;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Implementation of PKI Core {@link CertificateManagementService}
 * 
 */

// TODO: Using common intercepter for method entry logging
@Profiled
@Stateless
public class CertificateManagementServiceBean implements CertificateManagementService {

    @Inject
    CertificateManagerFactory certificateManagerFactory;

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    ImportCertificateManager importCertificateManager;

    @Inject
    Logger logger;

    @Inject
    CSRManager csrManager;

    @Override
    public Certificate createCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException {

        logger.debug("Invoked createCertificate in PKI Core");

        final Certificate certificate = certificateManagerFactory.getManager(certificateGenerationInfo).generateCertificate(certificateGenerationInfo);
        logger.debug("Completed creation of certificate in PKI Core");
        return certificate;
    }

    @Override
    public void updateCertificateStatusToExpired() throws CertificateStateChangeException {
        persistenceHelper.updateCertificateStatusToExpired();
    }

    @Override
    public Certificate reKeyCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException {

        logger.debug("Rekey certificate for CA Entity ");
        final Certificate certificate = certificateManagerFactory.getManager(certificateGenerationInfo).generateCertificate(certificateGenerationInfo);
        logger.debug("Completed rekey certificate for CA Entity in pki core");

        return certificate;
    }

    @Override
    public Certificate renewCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException {

        logger.debug("Renew certificate for CA Entity");
        final Certificate certificate = certificateManagerFactory.getManager(certificateGenerationInfo).generateCertificate(certificateGenerationInfo);
        logger.debug("Completed renew certificate for CA Entity in pki core ");

        return certificate;
    }

    @Override
    public PKCS10CertificationRequestHolder generateCSR(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateRequestGenerationException,
            CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException {

        logger.info("Exporting CSR for Root CA in pki core started ");

        final PKCS10CertificationRequestHolder certificationRequestHolder = csrManager.generateCSR(certificateGenerationInfo);

        logger.info("Exporting CSR for Root CA in pki core done ");

        return certificationRequestHolder;
    }

    @Override
    public void importCertificate(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCAException, InvalidCertificateException, InvalidOperationException {

        logger.debug("Importing certificate in pki core database {} ", caName);
        importCertificateManager.importCertificate(caName, x509Certificate);
        logger.info("Certificate imported successfully for CA: {}", caName);
    }

}
