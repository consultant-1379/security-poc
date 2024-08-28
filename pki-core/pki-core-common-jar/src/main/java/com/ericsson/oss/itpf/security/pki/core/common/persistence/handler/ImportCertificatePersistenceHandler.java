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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

/**
 * Handler class which does all persistence operations of import certificate.
 *
 */
public class ImportCertificatePersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    private static final String getLatestCertGenInfoOfCAQuery = "select cgf from CertificateGenerationInfoData cgf where  cgf.forExternalCA = true and cgf.cAEntityInfo in ( select ec.id from CertificateAuthorityData ec where ec.name = :name) ORDER BY cgf.id DESC";

    /**
     * This method gets latest {@link CertificateGenerationInfoData} object which has forExternalCA flag enabled.
     *
     * @param caEntityName
     *            name of the CA.
     * @return {@link CertificateGenerationInfoData} or null
     * 
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs
     * @throws CoreEntityNotFoundException
     *             thrown when certificate generation info not found for CA name.
     */
    public CertificateGenerationInfoData getLatestCertificateGenerationInfo(final String caEntityName) {

        logger.debug("Fetching certificate generation info of CA Entity : {}", caEntityName);
        try {
            final Query query = persistenceManager.getEntityManager().createQuery(getLatestCertGenInfoOfCAQuery);
            query.setParameter("name", caEntityName);
            query.setFirstResult(0);

            final List<CertificateGenerationInfoData> certificateGenerationInfoData = query.getResultList();
            if (!certificateGenerationInfoData.isEmpty()) {
                return certificateGenerationInfoData.get(0);
            } else {
                logger.error(ErrorMessages.CERTIFICATE_GENERATION_INFO_NOT_FOUND + " for the CA {}", caEntityName);
                systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "ImportCertificatePersistenceHandler",
                        "CertificateGenerationInfoData", "Certificate generation info not found in the system for CA : " + caEntityName);
                throw new CoreEntityNotFoundException(ErrorMessages.CERTIFICATE_GENERATION_INFO_NOT_FOUND + " for the CA " + caEntityName);
            }
        } catch (PersistenceException persistenceException) {
            logger.error("{} for the CA {}", ErrorMessages.ERROR_WHILE_IMPORT_CERT, caEntityName);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "ImportCertificatePersistenceHandler",
                    "CertificateGenerationInfoData", "Exception occurred when importing certificate signed by external CA for : " + caEntityName);
             throw new CertificateServiceException(ErrorMessages.ERROR_WHILE_IMPORT_CERT, persistenceException);
        }
    }

    /**
     * Stores the certificate for the Root CA and updates corresponding CertificateGenerationInfo.
     *
     * @param caName
     *            name of the CA
     * @param x509Certificate
     *            certificate to be stored in the db.
     * @throws CoreEntityNotFoundException
     *             Thrown in case given ca not found in the database.
     * @throws CertificateServiceException
     *             Thrown in case failure occurs storing the certificate.
     * @throws InvalidCertificateException
     *
     */
    public void importCertificateForRootCA(final String caName, final X509Certificate x509Certificate) throws CoreEntityNotFoundException, CertificateServiceException, InvalidCertificateException {

        logger.info("Import certificate for Root CA: {}", caName);
        final CertificateAuthorityData certificateAuthorityData = certificatePersistenceHelper.getCA(caName);

        final CertificateGenerationInfoData certificateGenerationInfoData = getLatestCertificateGenerationInfo(caName);

        final KeyIdentifierData keyIdentifierData = certificatePersistenceHelper.getActiveKeyIdentifier(caName);

        final CertificateData certificateData = certificatePersistenceHelper.storeAndReturnCertificate(x509Certificate, keyIdentifierData);

        certificateAuthorityData.setIssuerExternalCA(true);
        certificatePersistenceHelper.updateCAWithActiveCertificate(certificateData, certificateAuthorityData, null, CAStatus.ACTIVE);
        certificatePersistenceHelper.updateCertificateGenerationInfo(certificateGenerationInfoData, certificateData);
    }
}
