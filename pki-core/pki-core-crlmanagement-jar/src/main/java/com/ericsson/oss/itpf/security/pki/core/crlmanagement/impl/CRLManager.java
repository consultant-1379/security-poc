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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.model.util.CertificateAuthorityUtil;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidDurationFormatException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.CrlGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.persistence.handler.CRLPersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;

//TODO:getCRL by EntityName and Certificate details will be done as part of TORF-82410
public class CRLManager {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CRLPersistenceHelper crlPersistenceHelper;

    @Inject
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Inject
    CrlGeneratorFactory crlGeneratorFactory;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to get AllCRLs identified by CA Name and its Certificate Serial Number.
     *
     * @param caCertificateIdentifier
     *            CRL is retrieved using Certificate identified by{@link CACertificateIdentifier} object passed.
     * @return list of CRLInfo objects or null if CRL is not found for given CACertificateIdenitfier.
     *
     * @throws CertificateNotFoundException
     *             in case certificate does not exist.
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws InvalidCAException
     *             thrown for invalid CRLGenerationInfo or invalid CA data .
     */
    public List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertificateIdentifier) throws CertificateNotFoundException, CoreEntityNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("Retrieving ALLCRLs for CaEntity {}", caCertificateIdentifier.getCaName());
        CertificateAuthority certificateAuthority = null;
        try {
            certificateAuthority = crlPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName());
        } catch (final InvalidCertificateException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CERTIFICATE", ErrorSeverity.ERROR, "CRLManager", "Get CRL",
                    "Invalid certificate exception while generating CRL for CA : " + caCertificateIdentifier.getCaName());
            throw new InvalidCAException(exception);
        } catch (final InvalidCRLGenerationInfoException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT_INVALID_CRL_GENERATION_INFO", ErrorSeverity.ERROR, "CRLManager", "Get CRL",
                    "Invalid CRL Generation info for generating CRL for CA: " + caCertificateIdentifier.getCaName());
            throw new InvalidCAException(exception);
        }
        final Certificate certificate = getCertificate(certificateAuthority, caCertificateIdentifier.getCerficateSerialNumber());
        return getAllCRLs(certificateAuthority, certificate);
        
    }

    /**
     * This method is used to get Latest CRLs of corresponding CAs. In case the given CaName is not found or Certificate does not exists,or CRL is not found for CaEntity this method will not throw any
     * exceptions.Instead it will store null value for that particular CaEntity in the map object.
     *
     * @param caCertificateIdentifierList
     *            contains list of {@link CACertificateIdentifier} objects using which CRL is retrieved.
     * @return HashMap object which contains caCertificateIdentifier and corresponding CRLInfos.
     *
     * @throws CRLServiceException
     *             in case of any database failures.
     */
    public Map<CACertificateIdentifier, CRLInfo> getLatestCRLs(final List<CACertificateIdentifier> caCertificateIdentifierList) throws CRLServiceException {
        logger.debug("Retrieving LATEST CRLs for number of caCertificateIdentifier objects {}" , caCertificateIdentifierList.size());
        final HashMap<CACertificateIdentifier, CRLInfo> latestCRLsMap = new HashMap<>();
        for (final CACertificateIdentifier caCertificateIdentifier : caCertificateIdentifierList) {
            try {
                final CertificateAuthority certificateAuthority = crlPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName());
                final Certificate certificate = getCertificate(certificateAuthority, caCertificateIdentifier.getCerficateSerialNumber());
                final CRLInfo crl = getCRLByStatus(certificateAuthority, certificate, CRLStatus.LATEST);
                latestCRLsMap.put(caCertificateIdentifier, crl);
            } catch (CRLGenerationException | CoreEntityNotFoundException | CertificateNotFoundException | CRLNotFoundException | InvalidCRLGenerationInfoException | CertificateExpiredException
                    | CertificateRevokedException exception) {
                logger.debug("Error occured while getting Latest CRLs of corresponding CAs ", exception);
                systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT._ERROR_LATEST_CRL", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                        "Error occured while getting Latest CRLs of corresponding CAs : " + caCertificateIdentifier.getCaName());
                latestCRLsMap.put(caCertificateIdentifier, null);
            }
        }
        return latestCRLsMap;
    }

    /**
     * getCertificate is used to fetch the certificate details from the caentity for the given certificate serial number.
     *
     * @param certificateAuthority
     *            caentity object from which the certificate data is fetched.
     * @param certificateSerialNumber
     *            serial number of the certificate
     * @return Certificate object of the caentity with the given serial number.
     *
     * @throws CertificateExpiredException
     *             thrown when the certificate status is expired.
     * @throws CertificateNotFoundException
     *             thrown when the Certificate not found with the given certificateSerialNumber.
     * @throws CertificateRevokedException
     *             thrown when the certificate status is revoked.
     */
    private Certificate getCertificate(final CertificateAuthority certificateAuthority, final String certificateSerialNumber) throws CertificateExpiredException, CertificateNotFoundException,
            CertificateRevokedException {
        logger.debug("Retrieving certificate for certificate authority : {}", certificateAuthority.getName());
        if (certificateAuthority.getActiveCertificate() != null && certificateAuthority.getActiveCertificate().getSerialNumber().equals(certificateSerialNumber)) {
            return certificateAuthority.getActiveCertificate();
        } else {
            if (certificateAuthority.getInActiveCertificates() != null) {
                for (final Certificate certificate : certificateAuthority.getInActiveCertificates()) {
                    if (certificate.getSerialNumber().equals(certificateSerialNumber)) {
                        if (certificate.getStatus().equals(CertificateStatus.EXPIRED)) {
                            logger.error(ErrorMessages.CERTIFICATE_EXPIRED + "with certificate serial number {}" , certificateSerialNumber);
                            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CA_CERT_EXPIRED", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                                    "Certificate of CA " + certificateAuthority.getName() + " with serial number : " + certificateSerialNumber + " is expired.");
                            throw new CertificateExpiredException(ErrorMessages.CERTIFICATE_EXPIRED);
                        }
                        if (certificate.getStatus().equals(CertificateStatus.REVOKED)) {
                            logger.error(ErrorMessages.CERTIFICATE_REVOKED + "with certificate serial number {}" , certificateSerialNumber);
                            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CA_CERT_REVOKED", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                                    "Certificate of CA " + certificateAuthority.getName() + " with serial number : " + certificateSerialNumber + " is revoked.");
                            throw new CertificateRevokedException(ErrorMessages.CERTIFICATE_REVOKED);
                        }
                        return certificate;
                    }
                }
            }
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND + "with serial number {}" , certificateSerialNumber);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.GET_OR_GENERATE_CRL_FAILURE", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Certificate of CA " + certificateAuthority.getName() + " not found with serial number : " + certificateSerialNumber + ".");
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + "with the serial number" + certificateSerialNumber + "for the ca" + certificateAuthority.getName());
        }
    }

    /**
     * Retrieves CRLs based on certificateId and {@link CertificateAuthorityData}
     *
     * @param certificateAuthority
     *            CertificateAuthority Object
     * @param certificateId
     *            certificate Id present in database.
     * @return List<CRLInfo> list of CRL objects retrieved from database or null if CRL is not found in the database.
     */
    private List<CRLInfo> getAllCRLs(final CertificateAuthority certificateAuthority, final Certificate certificate) {
        final List<CRLInfo> caCrlList = certificateAuthority.getCrlInfo();
        final List<CRLInfo> caCertCrlList = new ArrayList<>();
        if (caCrlList.isEmpty()) {
            logger.error(ErrorMessages.CRL_NOT_FOUND + " for the CertificateAuthority{} " + certificateAuthority.getName());
            systemRecorder
                    .recordError("PKI_CORE_GET_CRL.NO_CRL_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "No CRL found which is issued by the CA: " + certificateAuthority.getName() + ".");
            return null;
        }
        for (final CRLInfo cRLInfo : caCrlList) {
            if (certificate.equals(cRLInfo.getIssuerCertificate())) {
                caCertCrlList.add(cRLInfo);
            }
        }
        if (caCertCrlList.isEmpty()) {
            logger.error(ErrorMessages.CRL_NOT_FOUND + " for the certificate serial number " + certificate.getSerialNumber());
            systemRecorder.recordError("PKI_CORE_GET_CRL.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "CRL not found which is issued by the certificate of CA : "
                    + certificateAuthority.getName() + " with serial number " + certificate.getSerialNumber() + ".");
            return null;
        }
        return caCertCrlList;
    }

    private CRLInfo getCRLByStatus(final CertificateAuthority certificateAuthority, final Certificate certificate, final CRLStatus status) throws CRLNotFoundException {
        final List<CRLInfo> caCrlList = certificateAuthority.getCrlInfo();

        logger.debug("Retrieving CRL by status for certificate authority : {}", certificateAuthority.getName());
        if (caCrlList.isEmpty()) {
            logger.error(ErrorMessages.CRL_NOT_FOUND + " for the CertificateAuthority  " + certificateAuthority.getName());
            systemRecorder.recordError("PKI_CORE_GET_CRL.NO_CRL_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "No CRL found which is issued by the CA : " + certificateAuthority.getName()
                    + ".");
            throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND);
        }
        for (final CRLInfo cRLInfo : caCrlList) {
            if (certificate.equals(cRLInfo.getIssuerCertificate())) {
                if (cRLInfo.getStatus().equals(status)) {
                    return cRLInfo;
                }
            }
        }
        logger.error(ErrorMessages.CRL_NOT_FOUND + " for the certificate serial number {} and CRL status {}" , certificate.getSerialNumber() , status);
        systemRecorder.recordError("PKI_CORE_GET_CRL.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL",
                "No CRL found which is issued by certificate of CA : " + certificateAuthority.getName() + " with serial number " + certificate.getSerialNumber() + ".");
        throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND);
    }

    /**
     * This method will invoke generateCrl method based on particular criteria. criteria1: generate crl when crl with max crl number for a particular
     * certificate has expired. criteria2: generate crl when crl for a particular certificate has latest status with a condition check.
     *
     * @param certificateAuthorityName
     *            name of the Certificate Authority for which CRL need to be generated.
     * @param certificate
     *            certificate for which CRL need to be generated.
     */
    public void generateCRL(final String certificateAuthorityName, final Certificate certificate) {
        logger.info("Start of generateCRL method in CRLManager class");
        CRLInfo crlInfo = new CRLInfo();

        try {
            try {
                crlInfo = crlPersistenceHelper.getCRLWithMaxCRLNumber(certificate.getId());
            } catch (final PersistenceException e) {
                logger.debug("Error while generating CRL ", e);
                generateCRL(new CACertificateIdentifier(certificateAuthorityName, certificate.getSerialNumber()));
            }

            if (crlInfo == null || crlInfo.getStatus() == CRLStatus.EXPIRED) {
                generateCRL(new CACertificateIdentifier(certificateAuthorityName, certificate.getSerialNumber()));
            }

            if (crlInfo != null && crlInfo.getStatus() == CRLStatus.LATEST) {
                final String overlapPeriodString = crlPersistenceHelper.getOverlapPeriodForCRL(crlInfo);

                if (overlapPeriodString != null) {
                    final Date crlNextUpdate = new Date(crlInfo.getNextUpdate().getTime());
                    try {
                        final Duration overlapPeriod = DateUtility.convertStringToDuration(overlapPeriodString);
                        overlapPeriod.negate().addTo(crlNextUpdate);
                    } catch (final InvalidDurationFormatException e) {
                        logger.debug(ErrorMessages.INTERNAL_ERROR, e);
                        logger.error(ErrorMessages.INTERNAL_ERROR, e.getMessage());
                    }

                    if (crlNextUpdate.compareTo(new Date()) <= 0) {
                        generateCRL(new CACertificateIdentifier(certificateAuthorityName, certificate.getSerialNumber()));
                    }
                }
            }

        } catch (CoreEntityNotFoundException | CRLServiceException | InvalidCRLExtensionException | CertificateExpiredException | CertificateRevokedException | CRLValidationException
                | CertificateNotFoundException | PersistenceException e) {
            logger.debug(ErrorMessages.AUTOMATIC_CRL_GENERATION_JOB_FAILED, e);
            logger.error(ErrorMessages.AUTOMATIC_CRL_GENERATION_JOB_FAILED, "for CA Certificate {}, {} - {}", certificateAuthorityName, certificate.getSerialNumber(), e.getMessage());
        }
        logger.info("End of generateCRL method in CRLManager class");
    }

    /**
     * This method will update CRL status to EXPIRED whose validity expired.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public void updateCRLStatusToExpired() throws CRLServiceException {
        crlPersistenceHelper.updateCRLStatusToExpired();
    }

    /**
     * This method will update CRL status to INVALID whose issuer certificate has revoked.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public void updateCRLStatusToInvalid() throws CRLServiceException {
        crlPersistenceHelper.updateCRLStatusToInvalid();
    }

    /**
     * This method is used to generateCRL for a given CA and Certificate serial number.
     *
     * @param caCertificateIdentifier
     *            CRLInfo is generated using Certificate identified by {@link CACertificateIdentifier} object.
     * @return CRLInfo object generated
     * @throws CertificateExpiredException
     *             thrown when the CRL request is received for an expired certificate.
     * @throws CertificateRevokedException
     *             thrown when the CRL request is received for a revoked certificate.
     * @throws CertificateNotFoundException
     *             in case the CA Certificate to issue CRL is not found.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     * @throws CRLGenerationException
     *             Thrown when any exception occurred during CRLGeneration.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when the invalid attribute is found in entity.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors in case of Revocation.
     */
    public CRLInfo generateCRL(final CACertificateIdentifier caCertificateIdentifier) throws CertificateExpiredException, CertificateRevokedException, CertificateNotFoundException,
            CoreEntityNotFoundException, CRLServiceException, CRLGenerationException, InvalidCoreEntityAttributeException, RevocationServiceException {
        logger.info("Retrieving ALLCRLs for CaEntity {}", caCertificateIdentifier.getCaName());
        CertificateAuthority certificateAuthority = null;
        try {
            certificateAuthority = crlPersistenceHelper.getCertificateAuthority(caCertificateIdentifier.getCaName());
        } catch (final InvalidCertificateException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CERTIFICATE", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Invalid certificate exception while generating CRL for : " + caCertificateIdentifier.getCaName());
            throw new CRLGenerationException(exception);
        } catch (final InvalidCRLGenerationInfoException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CRL_GENERATION_INFO", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Invalid CRL Generation info for generating CRL for : " + caCertificateIdentifier.getCaName());
            throw new CRLGenerationException(exception);
        }
        final Certificate certificate = getCertificate(certificateAuthority, caCertificateIdentifier.getCerficateSerialNumber());
        CRLInfo crlInfo = null;
        CrlGenerationInfo crlGenerationInfo = null;
        try {
            crlGenerationInfo = getCrlGenerationInfo(certificateAuthority, certificate);
        } catch (final CRLGenerationInfoNotFoundException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CRL_GENERATION_INFO_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "CRL Generation info not found for generating CRL for : " + caCertificateIdentifier.getCaName());
            throw new CRLGenerationException(exception);
        }
        try {
            crlInfo = crlGeneratorFactory.getCrlGenerator(certificateAuthority).generateCRL(certificateAuthority, certificate, crlGenerationInfo);
        } catch (final InvalidCRLExtensionException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CRL_EXTENSION", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Invalid CRL extension while generating CRL for : " + caCertificateIdentifier.getCaName());
            throw new CRLGenerationException(exception);
        }
        crlPersistenceHelper.updateCRLInfo(certificateAuthority, certificate.getSerialNumber(), crlInfo);
        logger.info("End of generateCRL method in CRLManager");
        systemRecorder
                .recordSecurityEvent("PKI_CORE_CRL_MANAGEMENT_UPDATE_CRL_INFO", "CRLManager",
                        "Generated CRL info for ca entity " + caCertificateIdentifier.getCaName(), "Generating CRL's", ErrorSeverity.INFORMATIONAL,
                        "SUCCESS");
        return crlInfo;
    }

    /**
     * This method will fetch the associated CrlGeneration info for given CA name and Certificate Serial Number
     *
     * @param certificateAuthority
     * @param certificate
     * @return
     * @throws CRLGenerationInfoNotFoundException
     *             Thrown when CRL Generation Info is null or empty.
     */
    private CrlGenerationInfo getCrlGenerationInfo(final CertificateAuthority certificateAuthority, final Certificate certificate) throws CRLGenerationInfoNotFoundException {
        logger.info("getCrlGenerationInfo method in CRLManager");
        if (certificateAuthority.getCrlGenerationInfo() != null) {
            for (final CrlGenerationInfo crlGenerationInfo : certificateAuthority.getCrlGenerationInfo()) {
                for (final Certificate crlGenerationCertificate : crlGenerationInfo.getCaCertificates()) {
                    if (crlGenerationCertificate.getSerialNumber() == certificate.getSerialNumber()) {
                        logger.info("End getCrlGenerationInfo method in CRLManager");
                        return crlGenerationInfo;
                    }
                }
            }
        }
        logger.error("Can not find associated CRL Informantion {}" , certificateAuthority.getName());
        systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.NO_CRLGENERATIONINFO_FOUND", ErrorSeverity.ERROR, "CRLManager", "Generate CRL",
                "No CRLGenerationInfo found for the Certificate Authority :" + certificateAuthority.getName() + ".");
        throw new CRLGenerationInfoNotFoundException("Can not find associated CRL Informantion");
    }

    /**
     * getCRL will get the CRL with the given CRLNumber and which is issued by the given CA
     *
     * @param caEntityName
     *            is the name of CAEntity.
     * @param crlNumber
     *            is the CRLNumber which is assigned to the CRL to identify CRL
     * @return CRLInfo object which contains the attributes like thisUpdate, nextUpdate,CRLNumber,CRLStatus.
     * @throws CoreEntityNotFoundException
     *             thrown when the entity not found in the system.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCAException
     *             thrown for invalid CA .
     */
    public CRLInfo getCRL(final String caEntityName, final CRLNumber crlNumber) throws CoreEntityNotFoundException, CRLNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("CRLNumber received as{}", crlNumber);
        CertificateAuthority certificateAuthority = null;
        try {
            certificateAuthority = crlPersistenceHelper.getCertificateAuthority(caEntityName);
        } catch (final InvalidCertificateException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CERTIFICATE", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Invalid certificate exception for CAs : " + caEntityName + " and crl number " + crlNumber.getSerialNumber());
            throw new InvalidCAException(exception);
        } catch (final InvalidCRLGenerationInfoException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CRL_GENERATION_INFO", ErrorSeverity.ERROR, "CRLManager", "Get/Generate CRL",
                    "Invalid crl generation info for CAs : " + caEntityName + " and crl number " + crlNumber.getSerialNumber());
            throw new InvalidCAException(exception);
        }
        if (certificateAuthority.getCrlInfo() == null) {
            logger.error(ErrorMessages.CRL_NOT_FOUND + " for the CA {}" , caEntityName);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.NO_CRL_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "No CRL found for the CA : " + certificateAuthority.getName() + ".");
            throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND + " for the CA " + caEntityName);
        }
        final List<CRLInfo> crlInfoList = certificateAuthority.getCrlInfo();
        for (final CRLInfo crlInfo : crlInfoList) {
            if (crlInfo.getCrlNumber().getSerialNumber().equals(crlNumber.getSerialNumber())) {
                return crlInfo;
            }
        }
        logger.error(ErrorMessages.CRL_NOT_FOUND + " for the CA {} with the CRLNumber {}" , caEntityName , crlNumber.getSerialNumber());
        systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL",
                "CRL not found for the Certificate authority : " + certificateAuthority.getName() + " with CRLNumber : " + crlNumber + ".");
        throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND + " for the CA " + caEntityName + " with the CRLNumber " + crlNumber.getSerialNumber());
    }

    /**
     * This method is used to get all CRLs which are issued by the certificate with given status and this certificate belongs to the given CA Entity.
     *
     * @param caEntityName
     *            is the name of the caEntity.
     * @param certificateStatus
     *            is the status of the Certificate which is used to identify the Certificate.
     * @return Map object which contains {@link CACertificateIdentifier} object as key and list of all {@link CRLInfo} objects as value. The caCertificateIdentifier object gives the certificate
     *         information of the given CAName and this certificate information is related to the issuer certificate of CRL.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate status.
     * @throws CoreEntityNotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during CRL fetching.
     * @throws InvalidCAException
     *             thrown for invalid CA.
     */
    public Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CertificateNotFoundException,
            CoreEntityNotFoundException, CRLServiceException, InvalidCAException {
        logger.debug("Retrieving all CRLs for CaEntity {}", caEntityName);
        CertificateAuthority certificateAuthority = null;
        try {
            certificateAuthority = crlPersistenceHelper.getCertificateAuthority(caEntityName);
        } catch (final InvalidCertificateException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CERTIFICATE", ErrorSeverity.ERROR, "CRLManager", "Get all CRLs",
                    "Invalid cerificate exception for the Certificate authority : " + caEntityName + ".");
            throw new InvalidCAException(exception);
        } catch (final InvalidCRLGenerationInfoException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INVALID_CRL_GENERATION_INFO", ErrorSeverity.ERROR, "CRLManager", "Get all CRLs",
                    "Invalid CRL generation info for: " + caEntityName + ".");
            throw new InvalidCAException(exception);
        }
        final List<Certificate> certList = CertificateAuthorityUtil.getCACertificatesByStatus(certificateAuthority, certificateStatus);
        if (certList.size() == 0) {
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND + " for CA {} with the certificateStatus {}" , caEntityName , certificateStatus);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get all CRLs", "No certificate found with status " + certificateStatus
                    + " for the Certificate authority : " + caEntityName + ".");
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + " for CA " + caEntityName + " with the certificateStatus " + certificateStatus);
        }
        final Map<CACertificateIdentifier, List<CRLInfo>> crlMap = new HashMap<>();
        CACertificateIdentifier caCertId = null;
        for (final Certificate certificate : certList) {
            try {
                caCertId = new CACertificateIdentifier(caEntityName, certificate.getSerialNumber());
                final List<CRLInfo> crlInfoList = getAllCRLs(certificateAuthority, certificate);
                crlMap.put(caCertId, crlInfoList);
            } catch (final CRLNotFoundException e) {
                logger.debug(ErrorMessages.CRL_NOT_FOUND, e);
                logger.error(ErrorMessages.CRL_NOT_FOUND + " for CA " + caEntityName);
                systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get all CRLs", "CRL not found for the certificate with status "
                        + certificateStatus + " for the Certificate authority : " + caEntityName + ".");
                crlMap.put(caCertId, null);
            }
        }
        return crlMap;
    }
}