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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateExpiredException;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCACRLsExistException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Class used for importing and listing the certificates of CAEntities.
 *
 * <p>
 *
 * Listing of certificates, return the list of certificates of CAEntity based on certificate status.
 * </p>
 */
@SuppressWarnings("squid:S1130")
public class ExtCAEntityManager {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Retrieve certificates of External CA entity.
     *
     * @param extCAName
     *            The External CA name.
     * @param certificateStatus
     *            The certificate status.
     * @return List of Certificate objects.
     *
     * @throws CertificateNotFoundException
     *             Throws in case of entity does not have certificate.
     * @throws EntityNotFoundException
     *             Thrown in case of given External CA does not exists.
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     * @throws InvalidEntityAttributeException
     *             Throws in case of the given entity has invalid attribute.
     */
    public List<Certificate> listCertificates(final String extCAName, final CertificateStatus... certificateStatus) throws CertificateServiceException, CertificateNotFoundException,
            EntityNotFoundException, InvalidEntityAttributeException {

        validateExtCAName(extCAName);

        try {
            CAEntityData issuerCAEntityData;
            issuerCAEntityData = caPersistenceHelper.getCAEntity(extCAName);
            if (issuerCAEntityData != null && !(issuerCAEntityData.isExternalCA())) {
                throw new EntityNotFoundException(ErrorMessages.CA_ISNT_EXTERNAL_CA);
            }
            final List<Certificate> certificates = caPersistenceHelper.getCertificatesForExtCA(extCAName, certificateStatus);
            if (certificates == null) {
                throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
            }
            return certificates;
        } catch (final CANotFoundException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex.getMessage());
            logger.debug(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "External CA: " + extCAName + " is not found.", "List External CA", ErrorSeverity.CRITICAL, "FAILURE");
            throw new EntityNotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
        } catch (final PersistenceException | EntityServiceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, exception);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", ErrorMessages.INTERNAL_ERROR, "List External CA", ErrorSeverity.CRITICAL, "FAILURE");
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR);
        } catch (final CertificateException | IOException certificateException) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, certificateException.getMessage());
            logger.debug(ErrorMessages.UNEXPECTED_ERROR, certificateException);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "Certificate encoding for external CA: " + extCAName + " is invalid.", "List External CA",
                    ErrorSeverity.CRITICAL, "FAILURE");
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + certificateException.getMessage());
        }
    }

    /**
     * @param extCAName
     */
    private void validateExtCAName(final String extCAName) throws MissingMandatoryFieldException {
        if (extCAName == null || extCAName.isEmpty()) {
            throw new MissingMandatoryFieldException(ErrorMessages.EXTERNAL_CA_NAME_EMPTY);
        }
    }

    /**
     * Import Certificate for External CA.
     *
     * @param extCAName
     *            The External CA name.
     * @param X509Certificate
     *            The X509 certificate to be imported.
     *
     * @throws CertificateFieldException
     *             Thrown in case of parse error on generate certificate.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws ExternalCAAlreadyExistsException
     *             Thrown in case the CA name is already used for another CA or External CA.
     * @throws ExternalCANotFoundException
     *             Throws when the External CA is not found in database.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown when internal db error occurs
     * @throws MissingMandatoryFieldException
     *             Throws in case of missing mandatory fields
     * @throws ExpiredCertificateException
     *             Throws in case when expired External CA certificate is imported.
     */
    public void importCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException, CertificateNotFoundException, ExternalCAAlreadyExistsException,
            ExternalCANotFoundException, ExternalCredentialMgmtServiceException, MissingMandatoryFieldException, ExpiredCertificateException {

        final Certificate certificate = getCertificate(extCAName, x509Certificate, enableRFCValidation);
        try {
            caPersistenceHelper.storeExtCACertificate(extCAName, certificate, true);
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, persistenceException);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", ErrorMessages.INTERNAL_ERROR, "Import External CA " + extCAName, ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, certificateNotFoundException.getMessage());
            logger.debug(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, certificateNotFoundException);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "Certificate for external CA: " + extCAName + " is not found.", "Import External CA",
                    ErrorSeverity.CRITICAL, "FAILURE");
            throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, certificateNotFoundException);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error(ErrorMessages.ISSUER_CA_NOT_FOUND, caNotFoundException.getMessage());
            logger.debug(ErrorMessages.ISSUER_CA_NOT_FOUND, caNotFoundException);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "issuer of external CA: " + extCAName + " is not found.", "Import External CA", ErrorSeverity.CRITICAL,
                    "FAILURE");
            throw new ExternalCANotFoundException(ErrorMessages.ISSUER_CA_NOT_FOUND, caNotFoundException);
        }
    }

    /**
     * This Method is used to import certificate for ExternalCA in case no chain validation is required.
     *
     * @param extCAName
     *            The External CA name.
     * @param X509Certificate
     *            The X509 certificate to be imported.
     *
     * @throws CertificateFieldException
     *             Thrown in case of parse error on generate certificate.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws ExternalCAAlreadyExistsException
     *             Thrown in case the CA name is already used for another CA or External CA.
     * @throws ExternalCANotFoundException
     *             Thrown when the External CA is not found in the database.
     * @throws ExternalCredentialMgmtServiceException
     *             Thown when internal db error occurs
     * @throws MissingMandatoryFieldException
     *             Thown when internal db error occurs Throws in case of missing mandatory fields
     * @throws ExpiredCertificateException
     *             Thrown in case when expired External CA certificate is imported.
     */
    public void forceImportCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException, CertificateNotFoundException, ExternalCAAlreadyExistsException,
            ExternalCANotFoundException, ExternalCredentialMgmtServiceException, MissingMandatoryFieldException, ExpiredCertificateException {

        final Certificate certificate = getCertificate(extCAName, x509Certificate, enableRFCValidation);
        try {
            caPersistenceHelper.storeExtCACertificate(extCAName, certificate, false);
        } catch (final CANotFoundException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex.getMessage());
            logger.debug(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "External CA: " + extCAName + " is not found.", "Import External CA", ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, persistenceException);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", ErrorMessages.INTERNAL_ERROR, "Import External CA " + extCAName, ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
    }

    private Certificate getCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws MissingMandatoryFieldException, ExpiredCertificateException {
        validateExtCAName(extCAName);

        if (x509Certificate == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.CERTIFICATE_EMPTY);
        }

        checkCertificateIsPresent(x509Certificate);
        validateExtCAcertificate(extCAName, x509Certificate, enableRFCValidation);

        final Certificate certificate = mappingX509ToCertificate(x509Certificate);
        return certificate;

    }

    private void validateExtCAcertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws ExpiredCertificateException, MissingMandatoryFieldException {
        logger.debug("Checking the validity of External CA's x509certificate[{}],it is valid from [{}] and is valid till [{}]", extCAName, x509Certificate.getNotBefore(), x509Certificate.getNotAfter());
        try {
            x509Certificate.checkValidity();
            if (enableRFCValidation) {
                 validateSubjectAndAuthorityKeyIdentifiers(x509Certificate);
            }
        } catch (final CertificateNotYetValidException | CertificateExpiredException exception) {
            final String errorMessage = ErrorMessages.EXPIRED_OR_NOT_YET_VALID_CERTIFICATE;
            logger.debug(errorMessage, exception.getMessage());
            logger.error(errorMessage, exception.getMessage());
            throw new ExpiredCertificateException(errorMessage);
        }

    }

    /**
     * Check if Certificate is already present.
     *
     * @param X509Certificate
     *            The X509 certificate to be imported.
     *
     * @throws CertificateAlreadyExistsException
     *             Throws in case of the certificate already exists.
     * @throws ExternalCredentialMgmtServiceException
     */

    private void checkCertificateIsPresent(final X509Certificate x509Certificate) throws ExternalCredentialMgmtServiceException, CertificateAlreadyExistsException {
        final String certificateDataQuery = "select c from CertificateData c where c.status=:active and c.serialNumber=:serial_number";

        // TODO DESPICABLE_US Refactoring certificateDataQuery with new Object Model

        final Map<String, Object> attributes = new HashMap<String, Object>();
        // TODO DESPICABLE_US query only for Certificate with Active State? or also Inactive?
        attributes.put("active", CertificateStatus.ACTIVE.getId());
        attributes.put("serial_number", x509Certificate.getSerialNumber().toString(16));
        final List<CertificateData> certificateList = persistenceManager.findEntitiesByAttributes(certificateDataQuery, attributes);
        for (final CertificateData certData : certificateList) {
            X509Certificate certificatePers;
            try {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(certData.getCertificate());
                certificatePers = (X509Certificate) certFactory.generateCertificate(inputStream);
            } catch (final CertificateException e) {
                throw new ExternalCredentialMgmtServiceException(e.getMessage(), e);
            }
            if (x509Certificate.getIssuerX500Principal().equals(certificatePers.getIssuerX500Principal())
                    && x509Certificate.getSubjectX500Principal().equals(certificatePers.getSubjectX500Principal())) {
                throw new CertificateAlreadyExistsException(ErrorMessages.CERTIFICATE_ALREADY_IMPORTED);
            }
        }
    }

    /**
     * Map the X509Certificate into Certificate
     *
     * @param X509Certificate
     *            The X509 certificate to be imported.
     *
     * @return Certificate
     */
    private Certificate mappingX509ToCertificate(final X509Certificate x509Certificate) {
        final Certificate certificate = mappingX509ToCertificateWithoutSubject(x509Certificate);
        certificate.setSubject(CertificateUtility.getSubject(x509Certificate.getSubjectX500Principal()));
        return certificate;
    }

    /**
     * Map the X509Certificate into Certificate without mapping subject for MS-4
     *
     * @param X509Certificate
     *            The X509 certificate to be imported.
     *
     * @return Certificate
     */
    private Certificate mappingX509ToCertificateWithoutSubject(final X509Certificate x509Certificate) {
        final Certificate certificate = new Certificate();
        certificate.setSerialNumber(x509Certificate.getSerialNumber().toString(16));
        certificate.setNotAfter(x509Certificate.getNotAfter());
        certificate.setNotBefore(x509Certificate.getNotBefore());
        certificate.setIssuedTime(new Date());
        certificate.setX509Certificate(x509Certificate);
        certificate.setStatus(CertificateStatus.ACTIVE);
        return certificate;
    }

    public void removeCertificate(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCACRLsExistException,
            ExternalCredentialMgmtServiceException {
        validateExtCAName(extCAName);

        try {
            final CAEntityData issuerCAEntityData = caPersistenceHelper.getCAEntity(extCAName);
            if (issuerCAEntityData != null && !(issuerCAEntityData.isExternalCA())) {
                throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
            }
            final List<String> trustProfiles = caPersistenceHelper.getTrustProfileNamesUsingExtCA(issuerCAEntityData);// Non sono sicura che il metodo debba stare nel caPersistenceHelper
            if (trustProfiles != null && !trustProfiles.isEmpty()) {
                throw new ExternalCAInUseException(ErrorMessages.EXTERNAL_CA_IS_USED);
            }

            if (issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData() != null) {
                throw new ExternalCACRLsExistException(ErrorMessages.EXTERNAL_CA_CRL_EXIST);
            }

            if (issuerCAEntityData.getAssociated() != null && issuerCAEntityData.getAssociated().size() > 0) {
                throw new ExternalCACRLsExistException(ErrorMessages.EXTERNAL_CA_CRL_EXIST);
            }

            final Set<CertificateData> caCertificates = issuerCAEntityData.getCertificateAuthorityData().getCertificateDatas();
            final List<Long> certificateIds = new ArrayList<Long>();

            for (final CertificateData certificate : caCertificates) {
                certificateIds.add(certificate.getId());
            }
            if (!certificateIds.isEmpty()) {
                final List<CertificateData> certificateDatas = caPersistenceHelper.getCertificateDatas(issuerCAEntityData.getId());

                if (certificateDatas != null) {
                    for (final CertificateData certificateData : certificateDatas) {
                        if (!certificateIds.contains(certificateData.getId())) {
                            throw new ExternalCAInUseException(String.format(ErrorMessages.EXTERNAL_CA_IS_USED_AS_ISSUER, extCAName));
                        }
                    }
                }
            }

            final Set<CertificateData> actualCertificates = issuerCAEntityData.getCertificateAuthorityData().getCertificateDatas();
            final Set<CertificateData> certificates = new HashSet<CertificateData>();
            for (final CertificateData certificate : actualCertificates) {
                certificate.setIssuerCA(null);
                persistenceManager.updateEntity(certificate);
                persistenceManager.refresh(certificate);
                certificates.add(certificate);
            }

            issuerCAEntityData.getCertificateAuthorityData().setCertificateDatas(new HashSet<CertificateData>());
            persistenceManager.updateEntity(issuerCAEntityData);
            persistenceManager.deleteEntity(issuerCAEntityData);

            for (final CertificateData certificate : certificates) {
                persistenceManager.deleteEntity(certificate);
            }

        } catch (final PersistenceException e) {
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, e);
        } catch (final CANotFoundException ex) {
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
        }
    }

    public X509Certificate getExternalCACertificate(final String extCAName, final String serialNumber) throws CertificateNotFoundException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, MissingMandatoryFieldException {

        validateExtCAName(extCAName);

        try {
            final CAEntityData issuerCAEntityData = caPersistenceHelper.getCAEntity(extCAName);
            if (issuerCAEntityData != null && !(issuerCAEntityData.isExternalCA())) {
                throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
            }

            if (serialNumber != null && !serialNumber.isEmpty()) {
                final Certificate cert = caPersistenceHelper.getExternalCACertificate(extCAName, serialNumber);
                if (cert == null) {
                    throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
                }
                return cert.getX509Certificate();
            } else {
                final List<Certificate> certificates = caPersistenceHelper.getCertificatesForExtCA(extCAName, CertificateStatus.ACTIVE);
                if (certificates == null) {
                    throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
                }
                final Certificate cert = certificates.get(0);
                return cert.getX509Certificate();
            }
        } catch (final CANotFoundException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex.getMessage());
            logger.debug(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "External CA: " + extCAName + " is not found.", "Export External CA", ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
        } catch (final CertificateException | IOException e) {
            logger.error(ErrorMessages.UNEXPECTED_ERROR, e.getMessage());
            logger.debug(ErrorMessages.UNEXPECTED_ERROR, e);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", "Certificate encoding for external: " + extCAName + " is invalid.", "Export External CA",
                    ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.UNEXPECTED_ERROR, e);
        } catch (final PersistenceException | EntityServiceException e) {
            logger.error(ErrorMessages.INTERNAL_ERROR, e.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, e);
            systemRecorder.recordSecurityEvent("External CA Service", "ExtCAEntityManager", ErrorMessages.INTERNAL_ERROR, "Export External CA " + extCAName, ErrorSeverity.CRITICAL, "FAILURE");
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }
    }

    private void validateSubjectAndAuthorityKeyIdentifiers(final X509Certificate x509Certificate) throws MissingMandatoryFieldException {
         logger.debug("Checking the Authority and Subject Key Identifiers in the External CA certificate");
         final byte[] authorityKeyIdentifier = x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
         final byte[] subjectKeyIdentifier = x509Certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
         if (authorityKeyIdentifier == null) {
             throw new MissingMandatoryFieldException(ErrorMessages.AUTHORITY_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE);
         } else if (subjectKeyIdentifier == null) {
             throw new MissingMandatoryFieldException(ErrorMessages.SUBJECT_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE);
         }
    }

}
