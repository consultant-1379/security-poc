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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.ImportCertificateCAValidator;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.ImportCertificatePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;

public class ImportCertificateManager {

    @Inject
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Inject
    ImportCertificateCAValidator importCertificateCAValidator;

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Imports certificate for the given CA if it is a Root CA.
     * 
     * @param caName
     *            name of the CA.
     * @param x509Certificate
     *            certificate to be imported.
     * 
     * @throws CertificateServiceException
     *             Thrown in case if any issue occurs while importing certificate.
     * @throws CoreEntityNotFoundException
     *             Thrown in case given CA does not exist in the database.
     * @throws CoreEntityServiceException
     *             Thrown in case of entity related errors in the database.
     * @throws InvalidCAException
     *             This exception is thrown when the given CAEntity is not valid.
     * @throws InvalidCertificateException
     *             Thrown in case if any issue occurs while importing certificate.
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     */
    public void importCertificate(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCAException, InvalidCertificateException, InvalidOperationException {
        importCertificateCAValidator.validate(caName);
        logger.info("CA Certificate validated successfully for : {}", caName);
        importCertificatePersistenceHandler.importCertificateForRootCA(caName, x509Certificate);
        systemRecorder.recordSecurityEvent("PKICore.CertificateManagement", "ImportCertificateManager",
                "Importing CA certificate for PKI core database", "Certificate imported successfully for CA: " + caName, ErrorSeverity.INFORMATIONAL,
                "SUCCESS");

    }

}
