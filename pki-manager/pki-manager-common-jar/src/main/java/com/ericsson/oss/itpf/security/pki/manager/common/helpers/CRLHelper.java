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
package com.ericsson.oss.itpf.security.pki.manager.common.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl.CRLPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * CRLHelper class is a helper class for handling CRUD operations of CRL like get,delete,update CRL and etc.
 *
 * @author xjagcho
 *
 */
public class CRLHelper {

    @Inject
    private CRLPersistenceHandler crlPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private Logger logger;

    /**
     * getCRLByCACertificate will fetch the latest CRL for a given CA Entity and its Certificate Serial Number.
     *
     * @param caCertificateIdentifier
     *            is the CA certificate information holder containing CA name and Certificate Serial number
     * @param isChainValidationRequired
     *            chain validation to be performed if this flag is true
     * @param isLatestCRLOnly
     *            only latest crl will fetch if this flag is true
     * @return CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate, CRLNumber, CRLStatus etc
     *
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate serial number.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws ExpiredCertificateException
     *             thrown when the fetch CRL request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown when invalid entity attribute is provided as part of the request.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    public CRLInfo getCRLByCACertificate(final CACertificateIdentifier caCertificateIdentifier, final boolean isChainValidationRequired, final boolean isLatestCRLOnly)
            throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLServiceException, ExpiredCertificateException,
            InvalidEntityAttributeException, RevokedCertificateException {
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName());
        final Certificate certificate = getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), isChainValidationRequired);
        return getCRL(caEntity, certificate, isLatestCRLOnly);
    }

    /**
     * getCRL is used to get the CRL from the caEntity.
     *
     * @param caEntity
     *            CAEntity object for which the CRLs are to be fetched
     * @param certificate
     *            CRL issuer certificate.
     * @return CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate, CRLNumber, CRLStatus etc
     * @throws CRLNotFoundException
     *             thrown when the CRL for the given CAEntity with the given certificate serial number is not present.
     */
    private CRLInfo getCRL(final CAEntity caEntity, final Certificate certificate, final boolean isLatestOnly) throws CRLNotFoundException {
        if (caEntity.getCertificateAuthority().getCrlInfo().size() == 0) {
            final String certAuthorityName = caEntity.getCertificateAuthority().getName();
            logger.error("No crl found for the ca {} " , certAuthorityName);
            throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND + " for the ca " + certAuthorityName);
        }
        boolean crlFound = false;
        for (final CRLInfo crlInfo : caEntity.getCertificateAuthority().getCrlInfo()) {
            if (crlInfo.getIssuerCertificate().getId() == certificate.getId() && crlInfo.getIssuerCertificate().getSerialNumber().equals(certificate.getSerialNumber())) {
                crlFound = true;
                if (!isLatestOnly || crlInfo.getStatus().equals(CRLStatus.LATEST)) {
                    return crlInfo;
                }
            }
        }
        if (!crlFound) {
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLHelper", "Get CRL", ErrorMessages.CRL_NOT_FOUND + " for the ca "
                    + caEntity.getCertificateAuthority().getName() + " with the certificate serial number " + certificate.getSerialNumber());
            throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND + " for the certificate with serial number " + certificate.getSerialNumber() + "for the CA "
                    + caEntity.getCertificateAuthority().getName());
        } else {
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLHelper", "Get CRL", ErrorMessages.NO_LATEST_CRL + " for the ca "
                    + caEntity.getCertificateAuthority().getName() + " with the certificate serial number " + certificate.getSerialNumber());
            throw new CRLNotFoundException(ErrorMessages.NO_LATEST_CRL + " for the certificate with serial number " + certificate.getSerialNumber() + " for the CA "
                    + caEntity.getCertificateAuthority().getName());
        }
    }

    /**
     * getCertificate is used to fetch the certificate details from the caentity for the given certificate serial number. Based on the flag chainValidation, certificate chain is validated
     *
     * @param caEntity
     *            caentity object from which the certificate data is fetched.
     * @param certificateSerialNumber
     *            serial number of the certificate
     * @param chainValidationRequired
     *            chain validation to be performed if flag is true
     * @return Certificate object of the caentity with the given serial number.
     *
     * @throws CertificateNotFoundException
     *             when certificate is not found.
     * @throws ExpiredCertificateException
     *             when any certificate in the chain is expired, this is thrown only if chain validation is needed.
     * @throws RevokedCertificateException
     *             when any certificate in the chain is revoked, this is thrown only if chain validation is needed.
     *
     */
    public Certificate getCertificate(final CAEntity caEntity, final String certificateSerialNumber, final boolean chainValidationRequired) throws CertificateNotFoundException,
            ExpiredCertificateException, RevokedCertificateException {
        logger.info("Fetching Certificate details from the CA entity {} and the certificate serial number {}" , caEntity, certificateSerialNumber);
        if (caEntity.getCertificateAuthority().getActiveCertificate() != null && caEntity.getCertificateAuthority().getActiveCertificate().getSerialNumber().equals(certificateSerialNumber)) {
            if (chainValidationRequired) {
                validateCertificateChain(caEntity.getCertificateAuthority().getActiveCertificate());
            }
            return caEntity.getCertificateAuthority().getActiveCertificate();
        } else {
            if (caEntity.getCertificateAuthority().getInActiveCertificates() != null) {
                for (final Certificate certificate : caEntity.getCertificateAuthority().getInActiveCertificates()) {
                    if (certificate.getSerialNumber().equals(certificateSerialNumber)) {
                        if (chainValidationRequired) {
                            validateCertificateChain(certificate);
                        }
                        return certificate;
                    }
                }
            }
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND + "with the serial number {} for the ca {}" , certificateSerialNumber , caEntity.getCertificateAuthority().getName());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "CRLHelper", "CRL", "Certificate not found with the serial number "
                    + certificateSerialNumber + " for the ca " + caEntity.getCertificateAuthority().getName());
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + "with the serial number " + certificateSerialNumber + "for the ca "
                    + caEntity.getCertificateAuthority().getName());
        }
    }

    /**
     * This method validates the certificate chain validation till root certificate.
     *
     * @param certificate
     *            it contains subject,issuer,issuerCertificate,RevokedTime and etc..
     * @throws ExpiredCertificateException
     *             thrown when the fetch CRL request is raised for an expired certificate.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    // This has to be made reusable where ever it is useful To do TORF-82625
    public void validateCertificateChain(final Certificate certificate) throws RevokedCertificateException, ExpiredCertificateException {

        if (certificate.getStatus().equals(CertificateStatus.REVOKED)) {
            logger.error(ErrorMessages.REVOKED_CERTIFICATE + "serial no: " + certificate.getSerialNumber());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CERTIFICATE_REVOKED", ErrorSeverity.ERROR, "CRLHelper", "CRL Management",
                    "The certificate is revoked with serial no: " + certificate.getSerialNumber());
            throw new RevokedCertificateException(ErrorMessages.REVOKED_CERTIFICATE + "serial no:" + certificate.getSerialNumber());
        }

        if (certificate.getNotAfter().before(new Date())) {
            logger.error(ErrorMessages.EXPIRED_CERTIFICATE + "serialno: " + certificate.getSerialNumber());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CERTIFICATE_EXPIRED", ErrorSeverity.ERROR, "CRLHelper", "CRL Management",
                    "The certificate is expired with serial no: " + certificate.getSerialNumber());
            throw new ExpiredCertificateException(ErrorMessages.EXPIRED_CERTIFICATE + "serialno:" + certificate.getSerialNumber());
        }

        if (certificate.getIssuerCertificate() != null) {
            validateCertificateChain(certificate.getIssuerCertificate());
        }
    }

    /**
     * This method updates the CRL information in DB Using crlInfo object for Revoked and Expired CA Certificates
     *
     * @param crlInfo
     *            it holds the CAName and Certificate Serial Number,CRL,CRL Number,CRL Status and ispublishedToCDPS etc.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     */
    public void updateCRLStatus(final CRLInfo crlInfo) throws  CRLServiceException {
        logger.debug("updateCRLStatus method in CRLHelper class using CRLInfo object");
        crlPersistenceHandler.updateCRLStatus(crlInfo);
        logger.debug("End of updateCRLStatus method in CRLHelper");
    }

    /**
     * This method gets the CRLInfo with status latest from DB
     *
     * @param crlStatus
     * @return return the List of CRLInfo object
     *
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> getAllCRLsWithLatestStatus(final CRLStatus crlStatus) throws CRLServiceException, InvalidCRLGenerationInfoException {
        return crlPersistenceHandler.getCRLInfoByStatus(crlStatus);
    }

    /**
     * This method will get the caName based on crlInfoId from DB
     *
     * @param crlInfoId
     *            id of the CRLInfo object for which the corresponding CA Name need to find.
     *
     * @return caName name of the CertificateAuthority which owns the crlInfo object
     */
    public String getCANameByCRL(final long crlInfoId) {
        return crlPersistenceHandler.getCANameByCRL(crlInfoId);
    }

    /**
     * This method is used get all eligible CRLs for Publishing to cdps on startup.
     *
     * @return CACertificateIdentifier list
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CACertificateIdentifier> getCRLsForPublishOnStartup() throws CRLServiceException, InvalidCRLGenerationInfoException {
        final List<CRLInfo> crlInfoList = crlPersistenceHandler.getCRLsToPublishToCDPS();

        final List<CRLInfo> publishCRLInfos = validateAndGetCRL(crlInfoList, CDPSPublishStatusType.PUBLISH);

        final List<CACertificateIdentifier> caCertificateIdentifiers = convertToCaCertIdentifier(publishCRLInfos);
        return caCertificateIdentifiers;
    }

    /**
     * This method is used get all eligible CRLs for UnPublishing to cdps on startup.
     *
     * @return CACertificateIdentifier list
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CACertificateIdentifier> getCRLsForUnpublishOnStartup() throws CRLServiceException, InvalidCRLGenerationInfoException {
        final List<CRLInfo> crlInfoList = crlPersistenceHandler.getAllCRLInfoByPublishedToCDPS(true);

        final List<CRLInfo> unPublishCRLInfos = validateAndGetCRL(crlInfoList, CDPSPublishStatusType.UNPUBLISH);

        final List<CACertificateIdentifier> caCertificateIdentifierList = convertToCaCertIdentifier(unPublishCRLInfos);
        return caCertificateIdentifierList;
    }

    /**
     * This method will validate and get eligible CRL's for for Publishing and UnPublishing
     *
     * @param crlInfos
     *            - CRLInfo List
     * @param cdpsPublishStatusType
     *            - publish , unpublish
     * @return - CRLInfo List
     */
    private List<CRLInfo> validateAndGetCRL(final List<CRLInfo> crlInfos, final CDPSPublishStatusType cdpsPublishStatusType) {
        final List<CRLInfo> validCRLs = new ArrayList<CRLInfo>();

        for (final CRLInfo crlInfo : crlInfos) {
            switch (cdpsPublishStatusType) {
            case PUBLISH:
                if (validateCRLForPublish(crlInfo)) {
                    validCRLs.add(crlInfo);
                }
                break;
            case UNPUBLISH:
                if (validateCRLForUnPublish(crlInfo)) {
                    validCRLs.add(crlInfo);
                }
                break;
            case UNKNOWN:
                logger.error(CDPSPublishStatusType.UNKNOWN + " CDPSPublishStatusType is not supported ");
                break;
            }
        }
        return validCRLs;
    }

    /**
     * Validate CRL for UnPublishing
     *
     * @param crlInfo
     *            - object which contains the attributes like X509CRL, thisUpdate, nextUpdate, CRLNumber, CRLStatus etc
     * @return - boolean
     */
    private boolean validateCRLForUnPublish(final CRLInfo crlInfo) {
        boolean isValidCRLForUnPublish = false;

        try {
            final CAEntity caEntity = getCAEntity(crlInfo.getId());
            final boolean isCRLPublishedToCDPS = caEntity.getCertificateAuthority().isPublishToCDPS();

            if (isCRLPublishedToCDPS && crlInfo.getStatus().equals(CRLStatus.LATEST)) {
                validateCertificateChain(crlInfo.getIssuerCertificate());
            } else {
                isValidCRLForUnPublish = true;
            }
        } catch (final CANotFoundException | CRLServiceException crlException) {
            logger.debug("CA is not found for CRL " + crlInfo.getId(), crlException);
        } catch (final RevokedCertificateException | ExpiredCertificateException certificateException) {
            isValidCRLForUnPublish = true;
            logger.debug("Validation chain failed for certificate " + crlInfo.getIssuerCertificate().getSerialNumber(), certificateException);
            logger.debug("CRL {} should be unpublish in CDPS for Revoked and Expired certificates", crlInfo.getId());
        }
        return isValidCRLForUnPublish;
    }

    /**
     * Validate CRL for Publishing
     *
     * @param crlInfo
     *            - object which contains the attributes like X509CRL, thisUpdate, nextUpdate, CRLNumber, CRLStatus etc
     * @return - boolean
     */
    private boolean validateCRLForPublish(final CRLInfo crlInfo) {
        boolean isValidCRLForPublish = false;

        try {
            final CAEntity caEntity = getCAEntity(crlInfo.getId());

            if (caEntity.getCertificateAuthority().isPublishToCDPS()) {
                validateCertificateChain(crlInfo.getIssuerCertificate());
                isValidCRLForPublish = true;
            }
        } catch (final CANotFoundException | CRLServiceException crlException) {
            logger.debug("CA is not found for CRL " + crlInfo.getId(), crlException);
        } catch (final RevokedCertificateException | ExpiredCertificateException certificateException) {
            logger.debug("Validation chain failed for certificate " + crlInfo.getIssuerCertificate().getSerialNumber(), certificateException);
            logger.debug("CRL {} should not publish in CDPS because of validation of certificate chain failed", crlInfo.getId());
        }

        return isValidCRLForPublish;
    }

    /**
     * This method will convert CRLInfo to CACertificateIdentifier
     *
     * @param crlInfos
     * @return - CACertificateIdentifier list
     */
    private List<CACertificateIdentifier> convertToCaCertIdentifier(final List<CRLInfo> crlInfos) {
        final Set<CACertificateIdentifier> caCertificateIdentifierSet = new HashSet<CACertificateIdentifier>();

        for (final CRLInfo crlInfo : crlInfos) {
            try {
                final CACertificateIdentifier caCertificateIdentifier = crlPersistenceHandler.getCACertificateIdentifierByCRL(crlInfo);
                caCertificateIdentifierSet.add(caCertificateIdentifier);
            } catch (final Exception exception) {
                logger.debug("Conversion failed for CRLInfo ", exception);
                logger.error("Conversion failed for CRLInfo " + crlInfo.getId());
            }
        }
        return new ArrayList<CACertificateIdentifier>(caCertificateIdentifierSet);
    }

    /**
     * Gets CAEntity for the given crl id.
     *
     * @param crlInfoId
     *            - CRL id
     * @return caEntity
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             Thrown if the given CAEntity not found in the database.
     * @throws CRLServiceException
     *             Thrown in case of any problem occurs while doing database operations.
     * @throws InvalidEntityAttributeException
     *             Thrown when invalid entity attribute is provided as part of the request.
     */
    private CAEntity getCAEntity(final long crlInfoId) throws CAEntityNotInternalException, CANotFoundException, CRLServiceException, InvalidEntityAttributeException {
        final String caName = getCANameByCRL(crlInfoId);
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caName);

        return caEntity;
    }

    /**
     * isCRLExists method is used to check whether crl exists for a certificate or not.If crl exists, isCRLExists method will return true.If crl does not exists for a certificate,isCRLExists method
     * will return false.
     *
     * @param caCRLInfoList
     *            list of CRLInfo objects of a caEntity.
     * @param certificate
     *            Certificate object for which crl existence is to be verified.
     */
    public boolean isCRLExists(final List<CRLInfo> caCRLInfoList, final Certificate certificate) {
        boolean isCRLFound = false;
        for (final CRLInfo crl : caCRLInfoList) {
            if (crl.getIssuerCertificate().getSerialNumber().equals(certificate.getSerialNumber())) {
                isCRLFound = true;
                break;

            }
        }
        return isCRLFound;
    }

    /**
     * This method will hard delete corresponding invalid crls for the caCertificateIdentifiers
     *
     * @param caCertificateIdentifiers
     *            List of CACertificateIdentifier objects whose CRLInfo need to delete from pki-manager db.
     *
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     *
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     **/
    public void deleteInvalidCRLs(final List<CACertificateIdentifier> caCertificateIdentifiers) throws CRLServiceException, CANotFoundException {
        logger.debug("Deleting invalid CRLs from pki-manager data base");
        crlPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);
        logger.debug("Invalid CRLs deleted from pki-manager data base");
    }

    /**
     * This method will return true if CRL exist and publish_to_cdps is true for the CAEntity identified by the given CACertificateIdentifier or else false.
     *
     * @param caCertificateIdentifier
     * @return boolean true if CRL exist and publish_to_cdps is true for the CAEntity identified by the given CACertificateIdentifier else false.
     *
     * @throws CAEntityNotInternalException
     *             thrown when the CAEntity is external CA.
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate serial number.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws ExpiredCertificateException
     *             thrown when the fetch CRL request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidProfileAttributeException
     *             thrown when the profile has invalid attribute.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    public boolean isCRLByCACertificateIdentifierPublishable(final CACertificateIdentifier caCertificateIdentifier) throws CAEntityNotInternalException, CANotFoundException,
            CertificateNotFoundException, CRLServiceException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName());
        final Certificate certificate = getCertificate(caEntity, caCertificateIdentifier.getCerficateSerialNumber(), false);
        CRLInfo crlinfo = null;
        try {
            crlinfo = getCRL(caEntity, certificate, false);
        } catch (final CRLNotFoundException e) {
            logger.debug("No CRL found. CRL Publishing skipped for the CA Certificate Identifier " + caCertificateIdentifier.toString());
        }
        final boolean isCACertificateIdCRLPublishable = (crlinfo != null && caEntity.getCertificateAuthority().isPublishToCDPS());
        return isCACertificateIdCRLPublishable;
    }

    /**
     * This method will get the CRL by calling CDPS URL of ExternalCA.
     * 
     * @param cdpsURL
     *            CDPS URL for fetching X509CRL.
     * 
     * @return x509Crl
     * 
     * @throws CertificateException
     *             indicates one of a variety of certificate problems.
     * 
     * @throws CRLException
     *             when any exception occur during CRl handling.
     * 
     * @throws CRLNotFoundException
     *             when the CRL for the given CA and Certificate SerialNumber is not present.
     * 
     * @throws IOException
     *             Signals that an I/O exception of some sort has occurred.
     * 
     * @throws MalformedURLException
     *             to indicate that a malformed URL has occurred. Either no legal protocol could be found in a specification string or the string could not be parsed.
     */
    public X509CRL getCRLFromExternalCDPS(final String cdpsURL) throws CertificateException, CRLException, CRLNotFoundException, IOException, MalformedURLException {

        if (cdpsURL.startsWith("http://")) {

            final URL url = new URL(cdpsURL);
            final InputStream crlStream = url.openStream();

            try {
                final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                final X509CRL x509Crl = (X509CRL) cf.generateCRL(crlStream);
                return x509Crl;
            } finally {
                crlStream.close();
            }

        } else {
            throw new CRLNotFoundException("Cannot download CRL from certificate " + "distribution point: " + cdpsURL);
        }

    }
}
