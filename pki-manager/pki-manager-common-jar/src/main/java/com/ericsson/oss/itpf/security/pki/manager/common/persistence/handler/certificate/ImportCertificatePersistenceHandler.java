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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.security.cert.*;

import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is responsible for handling the operations on certificate which is signed by external ca
 * 
 * @author tcschdy
 *
 */
public class ImportCertificatePersistenceHandler {

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    Logger logger;

    /**
     * This method is responsible for store certificate which is signed by external ca
     * 
     * @param caName
     *            name of the CA entity for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @throws CANotFoundException
     *             Throws in case of CAEntity not found in the database.
     * @throws CertificateException
     *             Thrown when error occurs while converting the x509Certificate to Certificate Object.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while getting the Certificate.
     * @throws EntityServiceException
     *             Thrown when internal db error occurs while getting the CA Entity.
     * @throws PersistenceException
     *             Thrown when internal db error occurs while storing the certificate.
     */
    public void storeCertificate(final String caName, final X509Certificate x509Certificate) throws CANotFoundException, CertificateException, InvalidOperationException, CertificateServiceException,
            EntityServiceException, PersistenceException {

        final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(caName);
        caEntityData.getCertificateAuthorityData().setIssuerExternalCA(true);

        final Certificate certificate = CertificateUtility.convertX509ToCertificate(x509Certificate);

        // Bouncycastle reverses SubjectDN and IssuerDN while issuing certificates. As a result IssuerDN in sub CA certificates does not match with SubjectDN of imported ExtenalCA signed PKI RootCA.
        // To prevent this as a work around, SubjectDN is reversed and stored in Certificate table for the imported certificate. This change is done as part of TORF-139992
        reverseSubjectDN(certificate);

        certificate.setStatus(CertificateStatus.ACTIVE);

        // Get the latest csr information generated for the root ca to be signed by external CA
        final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);

        // Store the certificate information in pkimanagerdb
        caCertificatePersistenceHelper.storeCertificate(caEntityData, certificateGenerationInfoData, certificate);

    }

    private void reverseSubjectDN(final Certificate certificate) throws CertificateParsingException {

        String reversedDN = null;
        try {
            reversedDN = CertificateUtility.getReversedSubjectDN(certificate.getSubject().toASN1String());
        } catch (InvalidNameException invalidNameException) {
            logger.error(ErrorMessages.INVALID_DN, invalidNameException.getMessage());
            throw new CertificateParsingException(ErrorMessages.INVALID_DN, invalidNameException);
        }
        Subject reversedSubject = new Subject();
        reversedSubject = reversedSubject.fromASN1String(reversedDN);
        certificate.setSubject(reversedSubject);
    }

    /**
     * This method sets the issuerCA and IssuerCertificate fields to certificate.
     * 
     * @param caName
     *            name of the CA entity for which IssuerCertificate needs to be set.
     * @param x509Certificate
     *            This is issuer certificate which will be set.
     * @throws CertificateNotFoundException
     *             Thrown when the issuer certificate is not found.
     * @throws CertificateServiceException
     *             Thrown when any internal db error occurs while updating the issuer CA certificate.
     * @throws PersistenceException
     *             is thrown if any error occurs while fetching data from database.
     */
    public void updateIssuerCAandCertificate(final String caName, final X509Certificate x509Certificate) throws CertificateNotFoundException, CertificateServiceException, PersistenceException {
        final CertificateData certificateData = extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate);
        if (certificateData == null) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
            throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
        }
        final CAEntityData caEntityData = extCACertificatePersistanceHandler.getCAEntityData(certificateData.getId());
        if (caEntityData == null) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, "for the given certificateId");
            throw new CertificateNotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + " for the given CertificateId");
        }
        caCertificatePersistenceHelper.updateIssuerCAandCertificate(caCertificatePersistenceHelper.getCertificateDatas(caName, CertificateStatus.ACTIVE).get(0), caEntityData, certificateData);

    }

}
