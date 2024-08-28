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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.model.util.CertificateAuthorityUtil;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidDurationFormatException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLExtensionException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl.CRLPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.eserviceref.CRLManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLPublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.validator.CertificateStatusValidator;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CACertificateIdentifierBuilder;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementCoreLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * Class used for listing the crls of CAEntities.
 * <p>
 * Listing of CRLs, return the list of CRLs of CAEntity based on certificate serial number and caentity.
 * </p>
 *
 * @author xbensar
 */
public class CRLManager {

    @Inject
    private CRLManagerEServiceProxy crlManagerEServiceProxy;

    @EJB
    private CRLManagementCoreLocalService crlManagementCoreLocalService;

    @Inject
    private CRLHelper crlHelper;

    @Inject
    private CRLPersistenceHandler crlPersistenceHandler;

    @Inject
    private CRLUnpublishNotifier crlUnpublishNotifier;

    @Inject
    private CRLPublishNotifier crlPublishNotifier;

    @Inject
    private CertificateStatusValidator certStatusValidator;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    /**
     * getCRLByCACertificate will fetch the latest CRL for a given CA Entity and its Certificate Serial Number.
     *
     * @param caCertificateIdentifier
     *            is the CA certificate information holder containing CA name and Certificate Serial number
     * @return CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate,CRLNumber,CRLStatus.
     * @throws CAEntityNotInternalException
     *             thrown when given CA is external CA
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
     * @throws InvalidCRLGenerationInfoException
     *             thrown when the CRL has invalid extension.
     * @throws InvalidEntityAttributeException
     *             thrown when the entity has invalid attribute.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    public CRLInfo getCRLByCACertificate(final CACertificateIdentifier caCertificateIdentifier) throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException,
            CRLNotFoundException, CRLServiceException, ExpiredCertificateException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException, RevokedCertificateException {
        try {
            return crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, true);
        } catch (final CRLNotFoundException e) {
            logger.debug("Error occured while fetching CRL for a given CA Entity and its Certificate Serial Number. ", e);
            try {
                generateCRL(caCertificateIdentifier);
            } catch (final CRLGenerationException exception) {
                logger.error("Invalid CRLGenerationInfo to generate CRL from getCrl when no CRL is found");
                System.out.println("CRLManager inside :: " + exception.getMessage());
                throw new CRLServiceException(ErrorMessages.ERROR_WHILE_GENERATING_CRL_FROM_GETCRL, exception);
            }
            return getCRLByCACertificate(caCertificateIdentifier);
        }
    }

    /**
     * getCRLbyCAName will retrieve latest CRLs of the CA's and its issuer Certificates CRLs up to ROOT CA based on Certificate Status
     *
     * @param caEntityName
     *            name of the entity for which the CRL has to be fetched
     * @param isChainRequired
     *            true if all the CRls up to the root CA need to be fetched. false if all the CRLs up to the rootCA are not required.
     * @param certificateStatus
     *            status of the certificate
     * @return HashMap object containing caCertificateIdentifier object as key and list of CRLInfo objects as value( CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate,
     *         CRLNumber, CRLStatus). caCertificateIdentifier object gives the certificate information of the given CAName and this certificate information is related to the issuer certificate of CRL.
     *         If chain is true then this CACertificateIdentifier represents the certificate which issued the first CRL in provided chain of CRLs as well as certificate of the given CA Name.
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CAEntityNotInternalException
     *             thrown when the given CA Entity is External CA.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given status.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCertificateStatusException
     *             thrown when the get CRL request is raised on expired and revoked certificate status.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public Map<CACertificateIdentifier, List<CRLInfo>> getCRLbyCAName(final String caEntityName, final CertificateStatus certificateStatus, final boolean isChainRequired) throws CANotFoundException,
            CAEntityNotInternalException, CertificateNotFoundException, CRLServiceException, InvalidCertificateStatusException, InvalidEntityAttributeException {
        logger.debug("CertificateStatus received as ", certificateStatus);
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caEntityName);
        final Map<CACertificateIdentifier, List<CRLInfo>> cRLInfoMap = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        CACertificateIdentifier caCertificateIdentifier = null;
        try {
            certStatusValidator.validate(certificateStatus);
        } catch (final ExpiredCertificateException e) {
            logger.error(ErrorMessages.EXPIRED_CERTIFICATE_STATUS);
            systemRecorder.recordError("PKI_MANAGER_GET_CRL_BY_CANAME.EXPIRED_CERTIFICATE_STATUS", ErrorSeverity.ERROR, "CRLManager", "getCRLbyCAName", ErrorMessages.EXPIRED_CERTIFICATE_STATUS);
            throw new InvalidCertificateStatusException(ErrorMessages.EXPIRED_CERTIFICATE_STATUS, e);
        } catch (final RevokedCertificateException e) {
            logger.error(ErrorMessages.REVOKED_CERTIFICATE_STATUS);
            systemRecorder.recordError("PKI_MANAGER_GET_CRL_BY_CANAME.REVOKED_CERTIFICATE_STATUS", ErrorSeverity.ERROR, "CRLManager", "getCRLbyCAName", ErrorMessages.REVOKED_CERTIFICATE_STATUS);
            throw new InvalidCertificateStatusException(ErrorMessages.REVOKED_CERTIFICATE_STATUS, e);
        }
        final List<Certificate> certificateList = getValidCACertificates(caEntity, certificateStatus);
        int count = certificateList.size();
        for (Certificate certificate : certificateList) {
            final List<CRLInfo> cRLInfoList = new ArrayList<CRLInfo>();
            try {
                crlHelper.validateCertificateChain(certificate);
                getLatestCRLList(caEntity.getCertificateAuthority(), certificate, isChainRequired, cRLInfoList);
                caCertificateIdentifier = new CACertificateIdentifier(caEntityName, certificate.getSerialNumber());
                cRLInfoMap.put(caCertificateIdentifier, cRLInfoList);
            } catch (final ExpiredCertificateException | RevokedCertificateException e) {
                logger.error("Exception Occured", e.getMessage());
                logger.debug("Certificate validation failed ", e);
                count--;
            } catch (final CRLNotFoundException e) {
                logger.error(ErrorMessages.NO_LATEST_CRL + " for the certificate with Id" + certificate.getId());
                logger.debug(ErrorMessages.CRL_NOT_FOUND, e);
                caCertificateIdentifier = new CACertificateIdentifier(caEntityName, certificate.getSerialNumber());
                cRLInfoMap.put(caCertificateIdentifier, null);
            }
        }
        if (count == 0) {
            logger.error(ErrorMessages.NO_VALID_CERTIFICATE);
            systemRecorder.recordError("PKI_MANAGER_GET_CRL_BY_CANAME.NO_VALID_CERTIFICATE", ErrorSeverity.ERROR, "CRLManager", "CRL", ErrorMessages.NO_VALID_CERTIFICATE + " for the CA "
                    + caEntityName);
            throw new CertificateNotFoundException(ErrorMessages.NO_VALID_CERTIFICATE);
        }

        return cRLInfoMap;
    }

    /**
     * This method is used to fetch all the CRLs for the given CA and certificate serial number.
     *
     * @param caCertificateIdentifier
     * @return list of CRL objects( CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate, CRLNumber, CRLStatus)
     * @throws CAEntityNotInternalException
     *             thrown when the given CA is external CA.
     * @throws CANotFoundException
     *             thrown when the given CA is not found.
     * @throws CertificateNotFoundException
     *             thrown when the given CA does not have any certificates.
     * @throws CRLGenerationException
     *             thrown when the CRL generation fails.
     * @throws CRLNotFoundException
     *             thrown when no CRL is found for the requested CA.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCAException
     *             thrown when the given CA does not have active certificates.
     * @throws InvalidCRLGenerationInfoException
     *             thrown when the CRL Generation failed due to invalid attribute.
     * @throws InvalidEntityAttributeException
     *             thrown when mapping CAEntity model to API
     */
    public List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertificateIdentifier) throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException,
            CRLGenerationException, CRLNotFoundException, CRLServiceException, InvalidCAException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException {
        logger.info("Fetching all the CRLs for the given CA {} and cerficate serialNumber {}" , caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber());
        boolean certFound = false;

        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caCertificateIdentifier.getCaName());

        if (caEntity.getCertificateAuthority().getActiveCertificate().getSerialNumber().equals(caCertificateIdentifier.getCerficateSerialNumber())) {
            certFound = true;
        } else {
            for (final Certificate certificate : caEntity.getCertificateAuthority().getInActiveCertificates()) {
                if (certificate.getSerialNumber().equals(caCertificateIdentifier.getCerficateSerialNumber())) {
                    certFound = true;
                    break;
                }
            }
        }

        if (!certFound) {
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.GET_ALL_CRLS", ErrorSeverity.ERROR, "CRLManager", "CRL", ErrorMessages.CERTIFICATE_NOT_FOUND + " for the CA{} "
                    + caCertificateIdentifier);
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + caEntity.getCertificateAuthority().getName() + "with the serial number"
                    + caCertificateIdentifier.getCerficateSerialNumber() + "for the ca" + caCertificateIdentifier.getCaName());
        }

        try {
            return getAllCrlsFromCore(caCertificateIdentifier);
        } catch (final CRLNotFoundException e) {
            generateCRL(caCertificateIdentifier);
            logger.debug(ErrorMessages.CRL_NOT_FOUND, e);
            return getAllCrlsFromCore(caCertificateIdentifier);
        }
    }

    private List<CRLInfo> getAllCrlsFromCore(final CACertificateIdentifier caCertificateIdentifier) throws CertificateNotFoundException, CRLNotFoundException, CRLServiceException, InvalidCAException {
        logger.info("Getting all CRL's from the core for the given CA {}" , caCertificateIdentifier.getCaName());
        List<CRLInfo> crlInfoList = null;
        try {
            crlInfoList = crlManagerEServiceProxy.getCoreCRLManagementService().getAllCRLs(caCertificateIdentifier);
            if (crlInfoList == null) {
                logger.error(ErrorMessages.CRL_NOT_FOUND);
                throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND);
            }

        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
            logger.error(e.getMessage());
            throw new CANotFoundException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException e) {
            logger.error(e.getMessage());
            throw new CertificateNotFoundException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException e) {
            logger.error(e.getMessage());
            throw new InvalidCAException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException e) {
            logger.error(e.getMessage());
            throw new CRLServiceException(e.getMessage(), e);
        }
        return crlInfoList;
    }

    /**
     * getLatestCRLList is used to fetch the latest CRL for the given CA Entity.
     *
     * @param ca
     *            CertificateAuthority object for which the CRL has to be fetched.
     * @param ca
     *            CertificateAuthority object for which the CRL has to be fetched.
     * @param certificate
     *            certificate object for which crls are fetched.
     * @param crlInfoList
     *            list of CRLInfo objects {@link CRLInfo}
     * @param isChainRequired
     *            if true, all the CRls up to the root CA are fetched. if false, then the latest CRL of the requested CA is fetched.
     * @throws CAEntityNotInternalException
     *             thrown when the given CA is external CA.
     * @throws CANotFoundException
     *             thrown when the given CA does not have any certificates.
     * @throws CertificateNotFoundException
     *             thrown when the given CA does not have any certificates.
     * @throws CRLNotFoundException
     *             thrown if Latest CRL is not found for the given CAEntity with the given Certificate as issuer.
     * @throws CRLGenerationException
     *             thrown when the CRL generation fails.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws EntityNotFoundException
     *             thrown when the given CA is not found
     * @throws InvalidCRLGenerationInfoException
     *             thrown when the failed to generate CRL due to invalid crl generation info.
     * @throws InvalidEntityAttributeException
     *             thrown when mapping CAEntity model to API
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    private void getLatestCRLList(final CertificateAuthority ca, final Certificate certificate, final boolean isChainRequired, final List<CRLInfo> crlInfoList) throws CAEntityNotInternalException,
            CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLGenerationException, CRLServiceException, EntityNotFoundException, InvalidCRLGenerationInfoException,
            InvalidEntityAttributeException, RevokedCertificateException {
        logger.debug("getLatestCRLList for CAEntity{} with the Certificate serialNumber{}", ca, certificate.getSerialNumber());
        CRLInfo crlForCA = null;
        final List<CRLInfo> caCRLInfoList = ca.getCrlInfo();
        if (caCRLInfoList.size() == 0 || !(crlHelper.isCRLExists(caCRLInfoList, certificate))) {
            final CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier(ca.getName(), certificate.getSerialNumber());
            try {
                logger.debug("generating CRL for the caEntity{}", ca);
                generateCRL(caCertIdentifier);
            } catch (final CRLGenerationException exception) {
                logger.error(ErrorMessages.ERROR_WHILE_GENERATING_CRL_FROM_GETCRL);
                throw new CRLGenerationException(ErrorMessages.ERROR_WHILE_GENERATING_CRL_FROM_GETCRL, exception);
            }
            final CAEntity caEntity = crlPersistenceHandler.getCAEntity(ca.getName());
            getLatestCRLList(caEntity.getCertificateAuthority(), certificate, isChainRequired, crlInfoList);
        } else {
            for (CRLInfo crlInfo : caCRLInfoList) {
                if (crlInfo.getStatus().equals(CRLStatus.LATEST) && crlInfo.getIssuerCertificate().getSerialNumber().equals(certificate.getSerialNumber())) {
                    crlForCA = crlInfo;
                    break;
                }
            }
            if (crlForCA == null) {
                logger.error(ErrorMessages.NO_LATEST_CRL + " for the CAEntity " + ca.getName());
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.LATEST_CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "GET CRL",
                        ErrorMessages.NO_LATEST_CRL + " for the CAEntity " + ca.getName());
                throw new CRLNotFoundException(ErrorMessages.NO_LATEST_CRL + " for the CAEntity " + ca.getName());
            }
            crlInfoList.add(crlForCA);
            if (!ca.isRootCA() && isChainRequired) {
                final String issuerName = certificate.getIssuer().getName();
                logger.debug("Issuer Name is:", issuerName);
                final CAEntity issuerCA = crlPersistenceHandler.getCAEntity(issuerName);
                getLatestCRLList(issuerCA.getCertificateAuthority(), certificate.getIssuerCertificate(), isChainRequired, crlInfoList);
            }
        }

    }

    /**
     * This method will update CRL status to EXPIRED whose validity expired.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public void updateCRLStatusToExpired() throws CRLServiceException, InvalidCRLGenerationInfoException {
        logger.info("updateCRLStatusToExpired method in CRLManager");
        final List<CACertificateIdentifier> caCertificateIdentifierList = crlPersistenceHandler.updateCRLStatusToExpired();
        crlUnpublishNotifier.notify(caCertificateIdentifierList, CRLUnpublishType.CRL_EXPIRED);
        logger.info("End of updateCRLStatusToExpired method in CRLManager");
    }

    /**
     * This method will notify CDPS service to unpublish CRLs whose issuer certificate has revoked or expired.
     * 
     * @throws CRLServiceException
     */
    public void unpublishInvalidCRLs() throws CRLServiceException, InvalidCRLGenerationInfoException {
        logger.info("unpublishInvalidCRLs method in CRLManager");
        final Set<CACertificateIdentifier> revokedCertCACertificateIdentifierSet = new HashSet<CACertificateIdentifier>();
        final Set<CACertificateIdentifier> expiredCertCACertificateIdentifierSet = new HashSet<CACertificateIdentifier>();

        final List<CRLInfo> crlInfoList = crlPersistenceHandler.getCRLInfoByStatus(CRLStatus.LATEST, CRLStatus.EXPIRED);
        if (crlInfoList != null) {
            for (final CRLInfo crlInfo : crlInfoList) {
                final Certificate crlIssuerCertificate = crlInfo.getIssuerCertificate();
                final String caName = crlPersistenceHandler.getCANameByCRL(crlInfo.getId());
                final CACertificateIdentifier caCert = new CACertificateIdentifier(caName, crlIssuerCertificate.getSerialNumber());
                if (crlIssuerCertificate.getStatus() == CertificateStatus.REVOKED) {
                    revokedCertCACertificateIdentifierSet.add(caCert);

                } else if (crlIssuerCertificate.getStatus() == CertificateStatus.EXPIRED) {
                    expiredCertCACertificateIdentifierSet.add(caCert);
                }
            }
        }
        unpublishCRLs(new ArrayList<CACertificateIdentifier>(revokedCertCACertificateIdentifierSet), CRLUnpublishType.REVOKED_CA_CERTIFICATE);
        unpublishCRLs(new ArrayList<CACertificateIdentifier>(expiredCertCACertificateIdentifierSet), CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        logger.info("End of unpublishInvalidCRLs method in CRLManager");
    }

    private void unpublishCRLs(final List<CACertificateIdentifier> caCertList, final CRLUnpublishType cRLUnpublishType) {
        if (caCertList != null && !caCertList.isEmpty()) {
            try {
                crlUnpublishNotifier.notify(caCertList, cRLUnpublishType);
            } catch (final Exception e) {
                logger.debug(ErrorMessages.FAIL_TO_UNPUBLISH_CRL, e);
                logger.error(ErrorMessages.FAIL_TO_UNPUBLISH_CRL + e.getMessage());
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRL_FAILURE", ErrorSeverity.ERROR, "CRLManager", "Unpublish CRL", ErrorMessages.FAIL_TO_UNPUBLISH_CRL);
            }
        }
    }

    /**
     * This method will get latest CRL for each ca certificate from pki-core. Fetched CRLs will be updated in the pki-manager data base.
     *
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     */
    public void getLatestCRLs() throws CRLServiceException {
        logger.info("The process started to fetch and update latest CRLs from pkicore database to pkimanager database");
        try {
            final List<CACertificateIdentifier> requiredCaCertificateIdentifierList = getRequiredCaCertificateIdentifierList();
            final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet = crlManagerEServiceProxy.getCoreCRLManagementService().getLatestCRLs(requiredCaCertificateIdentifierList);
            final Iterator<Map.Entry<CACertificateIdentifier, CRLInfo>> iterator = caCrlInfoHashMapToSet.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getValue() == null) {
                    iterator.remove();
                }
            }
            addOrUpdateLatestCRL(caCrlInfoHashMapToSet);
            logger.info("Latest CRLs have been fetched and updated successfully in pkimanager data base");
        } catch (final PersistenceException | CertificateServiceException | com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException | CertificateRevokedException e) {
            logger.error(ErrorMessages.INTERNAL_ERROR + e.getMessage());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "Internal error while fetching Latest CRLs.");
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }
    }

    private List<CACertificateIdentifier> getRequiredCaCertificateIdentifierList() {
        logger.debug("Entering method getRequiredCaCertificateIdentifierList in CRLManager");

        final List<CACertificateIdentifier> requiredCACertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = crlPersistenceHandler.getCACertCRLInfoMap();
        for (final Map.Entry<CACertificateIdentifier, CRLInfo> entry : caCertCRLInfoMap.entrySet()) {
            final CACertificateIdentifier caCertificateIdentifier = entry.getKey();
            try {
                final CRLInfo crlInfo = caCertCRLInfoMap.get(caCertificateIdentifier);
                if (crlInfo != null) {
                    if (crlInfo.getStatus() == CRLStatus.EXPIRED) {
                        requiredCACertificateIdentifierList.add(caCertificateIdentifier);
                    }
                    if (crlInfo.getStatus() == CRLStatus.LATEST) {
                        final String overlapPeriodString = crlPersistenceHandler.getOverlapPeriodForCRL(crlInfo);
                        if (overlapPeriodString != null) {
                            final Date crlNextUpdate = new Date(crlInfo.getNextUpdate().getTime());
                            try {
                                final Duration overlapPeriod = DateUtility.convertStringToDuration(overlapPeriodString);
                                overlapPeriod.negate().addTo(crlNextUpdate);
                            } catch (final InvalidDurationFormatException e) {
                                logger.warn(ErrorMessages.INTERNAL_ERROR, e.getMessage());
                                logger.debug(ErrorMessages.INTERNAL_ERROR, e);
                            }
                            if (crlNextUpdate.compareTo(new Date()) <= 0) {
                                requiredCACertificateIdentifierList.add(caCertificateIdentifier);
                            }
                        }
                    }
                } else {
                    requiredCACertificateIdentifierList.add(caCertificateIdentifier);
                }
            } catch (final Exception e) {
                logger.error(ErrorMessages.INTERNAL_ERROR + e.getMessage());
                logger.debug(ErrorMessages.INTERNAL_ERROR, e);
            }
        }
        logger.debug("End of getRequiredCaCertificateIdentifierList method in CRLManager");
        return requiredCACertificateIdentifierList;
    }

    private void publishCRLs(final Set<CACertificateIdentifier> caCertificateIdentifierSet) {
        logger.info("Publishing CRLs to CDPS service");
        final List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        for (final CACertificateIdentifier cacertId : caCertificateIdentifierSet) {
            if (crlHelper.isCRLByCACertificateIdentifierPublishable(cacertId)) {
                caCertificateIdentifierList.add(cacertId);
            }
        }
        try {
            crlPublishNotifier.notify(caCertificateIdentifierList);
        } catch (final Exception e) {
            logger.info(ErrorMessages.FAIL_TO_PUBLISH_CRL);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.PUBLISH_CRLS_FAILURE", ErrorSeverity.ERROR, "CRLManager", "Publish CRLs to CDPS", ErrorMessages.FAIL_TO_PUBLISH_CRL);
            logger.debug(ErrorMessages.FAIL_TO_PUBLISH_CRL, e);
        }
        logger.info("CRLs published to CDPS service");

    }

    /**
     * generateCRL method will generate a CRL for a given CA and Certificate serial number.
     *
     * @param caCertIdentifier
     *            is the CA certificate information holder containing CA name and Certificate serial number.
     * @throws CANotFoundException
     *             thrown when the given CA is not found.
     * @throws CertificateNotFoundException
     *             thrown when the Certificate does not exists with the given CAName and SerialNumber.
     * @throws CRLGenerationException
     *             thrown when CRL generation validations failed during the generation of CRL.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the generation of CRL.
     * @throws ExpiredCertificateException
     *             thrown when the CRL generation request is raised for an expired certificate.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     * @throws RevokedCertificateException
     *             thrown when the CRL generation request is raised for a revoked certificate.
     */
    public void generateCRL(final CACertificateIdentifier caCertIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLServiceException,
            ExpiredCertificateException, InvalidCRLGenerationInfoException, RevokedCertificateException {
        logger.info("Generating a CRL for the given CA {} and Certificate serial number {} ", caCertIdentifier.getCaName(), caCertIdentifier.getCerficateSerialNumber() );
        CRLInfo crlInfo = null;
        try {
            certificatePersistenceHelper.validateCertificateChain(caCertIdentifier, EnumSet.of(CertificateStatus.REVOKED, CertificateStatus.EXPIRED));
            crlInfo = crlManagerEServiceProxy.getCoreCRLManagementService().generateCRL(caCertIdentifier);

        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
            logger.error(e.getMessage());
            throw new CANotFoundException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationException e) {
            logger.error(e.getMessage(), e);
            throw new CRLGenerationException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException | com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException e) {
            logger.error(e.getMessage());
            throw new CRLServiceException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException e) {
            logger.error(e.getMessage());
            throw new CertificateNotFoundException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException e) {
            logger.error(e.getMessage());
            throw new InvalidCRLGenerationInfoException(e.getMessage(), e);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException certificateRevokedException) {
            logger.error(certificateRevokedException.getMessage());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.GENERATE_CRL", ErrorSeverity.ERROR, "CRLManager", "CRL Generation",
                    "CRL generation failed due to  " + certificateRevokedException.getMessage());
            throw new RevokedCertificateException(certificateRevokedException.getMessage(), certificateRevokedException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException | ExpiredCertificateException exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.GENERATE_CRL", ErrorSeverity.ERROR, "CRLManager", "CRL Generation", "CRL generation failed due to  " + exception.getMessage());
            throw new ExpiredCertificateException(exception.getMessage(), exception);
        }

        final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet = new HashMap<CACertificateIdentifier, CRLInfo>();
        caCrlInfoHashMapToSet.put(caCertIdentifier, crlInfo);
        addOrUpdateLatestCRL(caCrlInfoHashMapToSet);
        systemRecorder.recordSecurityEvent("PKIMANAGER_CRL_MANAGEMENT", "CRLManager", "CRLS Generated successfully by Certificate of CA " + caCertIdentifier.getCaName() + " with serial number "
                + caCertIdentifier.getCerficateSerialNumber(), "CRL_MANAGEMENT.GENERATE_CRL", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    private void addOrUpdateLatestCRL(final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet) throws PersistenceException, CRLServiceException {
        final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToUpdate = new HashMap<CACertificateIdentifier, CRLInfo>();
        for (CACertificateIdentifier caCertificateIdentifier : caCrlInfoHashMapToSet.keySet()) {
            CRLInfo crlInfoToUpdate = null;
            try {
                crlInfoToUpdate = crlHelper.getCRLByCACertificate(caCertificateIdentifier, true, false);
                logger.debug("Updating latest CRL for the CA {} with Certificate serial number {} ", caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber());
            } catch (final CRLNotFoundException e) {
                logger.debug("Inserting CRL for the CA {} with Certificate serial number {} ", caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber(), e);
            } catch (final Exception e) {
                logger.debug("Unable to fetch CRL for CA entity ", e);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.RETRIEVE_CRL_FAILURE", ErrorSeverity.ERROR, "CRLManager", "CRL Generation", "Unable to fetch CRL for CA entity {} "
                        + caCertificateIdentifier.getCaName());
                logger.error("Unable to fetch CRL for CA entity {} with Certificate {} - {} ", caCertificateIdentifier.getCaName(), caCertificateIdentifier.getCerficateSerialNumber(), e.getMessage());
            }
            caCrlInfoHashMapToUpdate.put(caCertificateIdentifier, crlInfoToUpdate);
        }
        crlPersistenceHandler.updateLatestCRL(caCrlInfoHashMapToUpdate, caCrlInfoHashMapToSet);
        publishCRLs(caCrlInfoHashMapToUpdate.keySet());
    }

    /**
     * This method Publish Latest CRLs to the CDPS using list of CANames and update CA's PublishToCDPS to True.
     *
     * @param caNames
     *            are the CANames Whose CRLs will be published
     * @return map object contains the key as CAName, value as corresponding CRL Publish UnPublish CRL Operation Status
     *
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the generation of CRL.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     */
    public Map<String, CRLPublishUnpublishStatus> publishCRLToCDPS(final List<String> caNames) throws CRLServiceException, CANotFoundException {
        logger.info("Publishing latest CRLs to the CDPS using CA names");
        final Map<String, CRLPublishUnpublishStatus> publishCRLMap = new HashMap<String, CRLPublishUnpublishStatus>();
        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        for (final String caName : caNames) {
            CAEntity caEntity = null;
            try {
                caEntity = crlPersistenceHandler.getCAEntity(caName);

            } catch (final CANotFoundException caNotFoundException) {
                logger.debug(ErrorMessages.CA_ENTITY_NOT_FOUND, caNotFoundException);
                logger.error("CAEntity is not found for {}", caName);
                publishCRLMap.put(caName, CRLPublishUnpublishStatus.CA_ENTITY_NOT_FOUND);
                continue;
            } catch (final CAEntityNotInternalException caEntityNotInternalException) {
                logger.debug("Given CA is external CA ", caEntityNotInternalException);
                logger.error("{} is an external CA ", caName);
                publishCRLMap.put(caName, CRLPublishUnpublishStatus.EXTERNAL_CA);
                continue;
            } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
                logger.debug("Invalid entity attribute is found for entity ", invalidEntityAttributeException);
                logger.error("Invalid entity attribute is found for entity {}", caName);
                publishCRLMap.put(caName, CRLPublishUnpublishStatus.INVALID_ENTITY_ATTRIBUTE);
                continue;
            } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
                logger.error("Invalid profile attribute is found for entity {}", caName);
                logger.debug("Invalid profile attribute is found for entity {}", invalidProfileAttributeException);
                publishCRLMap.put(caName, CRLPublishUnpublishStatus.INVALID_PROFILE_ATTRIBUTE);
                continue;
            }
            if (ValidationUtils.isNullOrEmpty(caEntity.getCertificateAuthority().getCrlInfo())) {
                logger.error("CRLInfos are not found for {}", caName);
                publishCRLMap.put(caName, CRLPublishUnpublishStatus.CRL_INFO_NOT_FOUND);
                continue;
            }
            final List<CACertificateIdentifier> caCertificateIdentifiersPublished = populatePublishCRLMapWithLatestCRL(caEntity, publishCRLMap, caName);

            caCertificateIdentifiers.addAll(caCertificateIdentifiersPublished);

        }

        if (!ValidationUtils.isNullOrEmpty(caCertificateIdentifiers)) {
            crlPublishNotifier.notify(caCertificateIdentifiers);
        }

        return publishCRLMap;
    }

    /**
     * This method unPublish CRLs of the given CAs and update their PublishToCDPS value to false.
     *
     * @param caNames
     *            are the CANames Whose CRLs will be unpublished
     * @return map object contains the key as CAName ,value as corresponding CRL Publish UnPublish Status
     *
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the generation of CRL.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     */
    public Map<String, CRLPublishUnpublishStatus> unpublishCRLFromCDPS(final List<String> caNames) throws CRLServiceException, CANotFoundException {
        logger.info("Unpublishing the CRLs of the given CAs ");
        final Map<String, CRLPublishUnpublishStatus> unpulblishCRLMap = new HashMap<String, CRLPublishUnpublishStatus>();
        final Set<CACertificateIdentifier> caCertificateIdentifiers = new HashSet<CACertificateIdentifier>();
        List<CACertificateIdentifier> caCertificateIdentifiersList = null;
        for (String caName : caNames) {
            CAEntity caEntity = null;
            try {
                caEntity = crlPersistenceHandler.getCAEntity(caName);
            } catch (final CANotFoundException caNotFoundException) {
                logger.error("CAEntity is not found for {}", caName);
                logger.debug("CAEntity is not found for {}", caNotFoundException);
                unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.CA_ENTITY_NOT_FOUND);
                continue;
            } catch (final CAEntityNotInternalException caEntityNotInternalException) {
                logger.error("{} is an external CA ", caName);
                logger.debug("{} is an external CA ", caEntityNotInternalException);
                unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.EXTERNAL_CA);
                continue;
            } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
                logger.error("Invalid entity attribute is found for entity {}", caName);
                logger.debug("Invalid entity attribute is found for entity {}", invalidEntityAttributeException);
                unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.INVALID_ENTITY_ATTRIBUTE);
                continue;
            } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
                logger.error("Invalid profile attribute is found for entity {}", caName);
                logger.debug("Invalid profile attribute is found for entity {}", invalidProfileAttributeException);
                unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.INVALID_PROFILE_ATTRIBUTE);
                continue;
            }
            final List<CRLInfo> crlInfos = caEntity.getCertificateAuthority().getCrlInfo();
            if (ValidationUtils.isNullOrEmpty(crlInfos)) {
                logger.error("Valid crl infos are not found for {}", caName);
                unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.CRL_INFO_NOT_FOUND);
                continue;
            }
            for (CRLInfo crlInfo : crlInfos) {
                updatePublishToCDPSForCAEnity(caEntity, false);
                final CACertificateIdentifier caCertificateIdentifier = (new CACertificateIdentifierBuilder()).caName(caName).cerficateSerialNumber(crlInfo.getIssuerCertificate().getSerialNumber())
                        .build();
                caCertificateIdentifiers.add(caCertificateIdentifier);
            }

            unpulblishCRLMap.put(caName, CRLPublishUnpublishStatus.SENT_FOR_UNPUBLISH);
        }
        caCertificateIdentifiersList = new ArrayList<CACertificateIdentifier>(caCertificateIdentifiers);
        if (!ValidationUtils.isNullOrEmpty(caCertificateIdentifiersList)) {
            crlUnpublishNotifier.notify(caCertificateIdentifiersList, CRLUnpublishType.USER_INVOKED_REQUEST);
        }
        return unpulblishCRLMap;
    }

    private void updatePublishToCDPSForCAEnity(final CAEntity caEntity, final boolean publishToCDPS) throws CRLServiceException, CANotFoundException {
        try {
            if (caEntity.getCertificateAuthority().isPublishToCDPS() != publishToCDPS) {
                try {
                    crlPersistenceHandler.updateCAEnity(caEntity, publishToCDPS);
                } catch (final EntityNotFoundException entityNotFoundException) {
                    logger.error("CA Entity is not found for : [{}]" , caEntity.getEntityProfile().getName());
                    throw new CANotFoundException(entityNotFoundException.getMessage(), entityNotFoundException);
                }
            }
        } catch (final CRLServiceException exception) {
            logger.error("Failed to update PublishToCDPS of CAEntity for {}", caEntity);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.PUBLISH_CRLS", ErrorSeverity.ERROR, "CRLManager", "Publish CRL to CDPS", "Failed to update PublishToCDPS of CAEntity " + caEntity);
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }
    }

    private List<CACertificateIdentifier> populatePublishCRLMapWithLatestCRL(final CAEntity caEntity, final Map<String, CRLPublishUnpublishStatus> publishCRLMap, final String caName)
            throws CRLServiceException, CANotFoundException {
        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        int resultCount = 0;
        for (CRLInfo crlInfo : caEntity.getCertificateAuthority().getCrlInfo()) {
            if (crlInfo.getStatus().getId() == CRLStatus.LATEST.getId()) {
                final Certificate certificate = crlInfo.getIssuerCertificate();
                try {
                    crlHelper.validateCertificateChain(certificate);
                } catch (final RevokedCertificateException | ExpiredCertificateException exception) {
                    logger.error("Certificate validation is failed {}", certificate);
                    logger.debug("Certificate validation failed ", exception);
                    continue;
                }
                updatePublishToCDPSForCAEnity(caEntity, true);

                final CACertificateIdentifier caCertificateIdentifier = (new CACertificateIdentifierBuilder()).caName(caName).cerficateSerialNumber(certificate.getSerialNumber()).build();
                caCertificateIdentifiers.add(caCertificateIdentifier);
                resultCount++;
            }
        }
        if (resultCount == 0) {
            publishCRLMap.put(caName, CRLPublishUnpublishStatus.VALID_CRL_NOT_FOUND);
        } else {
            publishCRLMap.put(caName, CRLPublishUnpublishStatus.SENT_FOR_PUBLISH);
        }
        return new ArrayList<CACertificateIdentifier>(caCertificateIdentifiers);
    }

    /**
     * getCRL will get the CRL with the given CRLNumber and which is issued by the given CA
     *
     * @param caEntityName
     *            is the name of CAEntity.
     * @param crlNumber
     *            is the CRLNumber which is assigned to the CRL to identify CRL
     * @return CRLInfo object which contains the attributes like thisUpdate, nextUpdate,CRLNumber,CRLStatus.
     *
     * @throws CAEntityNotInternalException
     *             thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCAException
     *             Thrown when the CA is not active.
     * @throws InvalidEntityAttributeException
     *             Thrown when invalid entity attribute is provided as part of the request.
     */
    public CRLInfo getCRLByCRLNumber(final String caEntityName, final CRLNumber crlNumber) throws CAEntityNotInternalException, CANotFoundException, CRLNotFoundException, CRLServiceException,
            InvalidCAException, InvalidEntityAttributeException {
        logger.debug("getCRLByCRLNumber method in CRLManager class received inputs CA name {} and crl number {}", caEntityName, crlNumber);
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caEntityName);
        CRLInfo cRLInfo = null;
        final List<CRLInfo> crlInfoList = caEntity.getCertificateAuthority().getCrlInfo();
        for (CRLInfo crlInfo : crlInfoList) {
            if (crlInfo.getCrlNumber().getSerialNumber().equals(crlNumber.getSerialNumber())) {
                cRLInfo = crlInfo;
            }
        }
        if (cRLInfo == null) {
            try {
                cRLInfo = crlManagerEServiceProxy.getCoreCRLManagementService().getCRL(caEntityName, crlNumber);
            } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
                logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND + " with the name " + caEntityName);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CA_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "CAEntity not found with the name " + caEntityName);
                throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + " with the name " + caEntityName, e);
            } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLNotFoundException e) {
                logger.error(ErrorMessages.CRL_NOT_FOUND + " for the CA " + caEntityName + " with the CRlNumber " + crlNumber.getSerialNumber());
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "No crl found for the CA " + caEntityName + " with the CRlNumber "
                        + crlNumber.getSerialNumber());
                throw new CRLNotFoundException(ErrorMessages.CRL_NOT_FOUND + " for the CA " + caEntityName + " with the CRlNumber " + crlNumber.getSerialNumber(), e);
            } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException e) {
                logger.error(ErrorMessages.INACTIVE_CA + " for getting all CRLs of CA " + caEntityName, e);
                throw new InvalidCAException(ErrorMessages.INACTIVE_CA + " for getting all CRLs of CA " + caEntityName);
            } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException e) {
                logger.error(ErrorMessages.INTERNAL_ERROR);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "Exception occured while getting CRL or the CA " + caEntityName
                        + " with the CRlNumber " + crlNumber.getSerialNumber());
                throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, e);
            }
        }
        return cRLInfo;
    }

    /**
     * generateCRL method will generate CRLs by the certificates which are identified by the given CA Names and Certificate Statuses. CRLs will only be generated by certificates with "ACTIVE" and
     * "INACTIVE" statuses. This method will return a map which contains {@link CACertificateIdentifier} as key and {@link CRLGenerationStatus} as value. If the provided certificateStatus is "ACTIVE"
     * then the map will contain CACertificateIdentifier related to active certificate and its {@link CRLGenerationStatus} value, If it is "INACTIVE" then map contains CACertificateIdentifier related
     * to inactive certificates and their {@link CRLGenerationStatus} value. If certificateStatus contains both "ACTIVE" and "INACTIVE", then map contains CACertificateIdentifier related to active and
     * inactive certificates and their corresponding {@link CRLGenerationStatus} values.
     *
     * @param caEntityNameList
     *            is the list of CAEntity names.
     * @param certificateStatus
     *            The {@link CertificateStatus} values by which certificates are identified to generate CRL.
     * @return Map object which contains {@link CACertificateIdentifier} as key and {@link CRLGenerationStatus} as value.
     * @throws InvalidCertificateStatusException
     *             thrown when "EXPIRED" or "REVOKED" certificate status is provided for generating CRL.
     *
     */
    public Map<CACertificateIdentifier, CRLGenerationStatus> generateCRL(final List<String> caEntityNameList, final CertificateStatus... certificateStatus) throws InvalidCertificateStatusException {
        logger.info("Generating CRLs for a list of CA Names and certificateStatuses");
        final CertificateStatus[] uniqueCertStatus = new HashSet<CertificateStatus>(Arrays.asList(certificateStatus)).toArray(new CertificateStatus[0]);
        try {
            certStatusValidator.validate(uniqueCertStatus);
        } catch (final ExpiredCertificateException e) {
            logger.error(ErrorMessages.EXPIRED_CERTIFICATE_STATUS);
            systemRecorder.recordError("PKI_MANAGER_GENERATE_CRL.EXPIRED_CERTIFICATE_STATUS", ErrorSeverity.ERROR, "CRLManager", "Generate CRL",
                    "CRL Generation failed : Certificate status Expired is invalid status to generate CRL");
            throw new InvalidCertificateStatusException(ErrorMessages.EXPIRED_CERTIFICATE_STATUS, e);
        } catch (final RevokedCertificateException e) {
            logger.error(ErrorMessages.REVOKED_CERTIFICATE_STATUS);
            systemRecorder.recordError("PKI_MANAGER_GENERATE_CRL.REVOKED_CERTIFICATE_STATUS", ErrorSeverity.ERROR, "CRLManager", "Generate CRL",
                    "CRL Generation failed : Certificate status Revoked is invalid status to generate CRL");
            throw new InvalidCertificateStatusException(ErrorMessages.REVOKED_CERTIFICATE_STATUS, e);
        }
        CACertificateIdentifier caCertificateIdentifier = null;
        final Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationStatusMap = new HashMap<CACertificateIdentifier, CRLGenerationStatus>();
        final Map<CACertificateIdentifier, CRLInfo> updateLatestCRLMap = new HashMap<CACertificateIdentifier, CRLInfo>();
        CRLInfo crlInfo = null;
        for (String caName : caEntityNameList) {
            try {
                final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caName);
                for (CertificateStatus certStatus : uniqueCertStatus) {
                    List<Certificate> certList;
                    logger.debug("CertificateStatus received as::", certStatus);
                    try {
                        certList = getValidCACertificates(caEntity, certStatus);
                    } catch (final CertificateNotFoundException certificateNotFoundException) {
                        logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND, certificateNotFoundException);
                        caCertificateIdentifier = new CACertificateIdentifier(caName, null);
                        crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CERTIFICATE_NOT_FOUND);
                        continue;
                    }
                    for (Certificate cert : certList) {
                        updateLatestCRLMap.clear();
                        caCertificateIdentifier = new CACertificateIdentifier(caName, cert.getSerialNumber());
                        try {
                            logger.debug("Generating CRL for CACertificateIdentifier{}", caCertificateIdentifier);
                            crlInfo = crlManagementCoreLocalService.generateCrl(caCertificateIdentifier);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL);
                            updateLatestCRLMap.put(caCertificateIdentifier, crlInfo);
                            addOrUpdateLatestCRL(updateLatestCRLMap);
                        } catch (final CANotFoundException | CoreEntityNotFoundException | InvalidCAException e) {
                            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, e);
                            caCertificateIdentifier = new CACertificateIdentifier(caName, null);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CA_ENTITY_NOT_FOUND);
                        } catch (final CertificateNotFoundException e) {
                            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND, e);
                            caCertificateIdentifier = new CACertificateIdentifier(caName, null);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CERTIFICATE_NOT_FOUND);

                        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationException | InvalidCRLExtensionException
                                | com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationInfoNotFoundException | InvalidCRLGenerationInfoException e) {
                            logger.error(CRLGenerationStatus.CRLGENERATION_INFO_NOT_FOUND.getValue(), e);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CRLGENERATION_INFO_NOT_FOUND);
                        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException e) {
                            logger.error(CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID.getValue(), e);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID);
                        } catch (final PersistenceException | com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException
                                | com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException
                                | com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException e) {
                            logger.error(CRLGenerationStatus.GENERATE_CRL_ERROR.getValue(), e);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.GENERATE_CRL_ERROR);
                        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException | ExpiredCertificateException
                                | com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException | RevokedCertificateException e) {
                            logger.error(CRLGenerationStatus.NO_VALID_CERTIFICATE_FOUND.getValue(), e);
                            crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.NO_VALID_CERTIFICATE_FOUND);
                        }
                    }
                }
            } catch (final CANotFoundException e) {
                logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, e);
                caCertificateIdentifier = new CACertificateIdentifier(caName, null);
                crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CA_ENTITY_NOT_FOUND);
            } catch (final CAEntityNotInternalException e) {
                logger.error(CRLGenerationStatus.CA_ENTITY_NOT_FOUND.getValue(), e);
                crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CA_ENTITY_NOT_FOUND);
            } catch (final InvalidEntityAttributeException e) {
                logger.error(CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID.getValue(), e);
                crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID);
            } catch (final CRLServiceException e) {
                logger.error(CRLGenerationStatus.GENERATE_CRL_ERROR.getValue(), e);
                crlGenerationStatusMap.put(caCertificateIdentifier, CRLGenerationStatus.GENERATE_CRL_ERROR);
            }
        }
        return crlGenerationStatusMap;
    }

    /**
     * getAllCRLs is used to fetch all CRLs which are issued by the certificate with the given status and this certificate belongs to the given CA Entity.
     *
     * @param caEntityName
     *            is the name of CAEntity.
     * @param certificateStatus
     *            is used to identify the certificate to get all CRLs.
     * @return Map object which contains {@link CACertificateIdentifier} object as key and list of all {@link CRLInfo} objects as value. caCertificateIdentifier object gives the certificate
     *         information of the given CAName and this certificate information is related to the issuer certificate of CRL.
     * @throws CAEntityNotInternalException
     *             thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate status.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during CRL fetching.
     * @throws InvalidCAException
     *             thrown when the CA is invalid for the operation.
     * @throws InvalidEntityAttributeException
     *             Thrown when invalid entity attribute is provided as part of the request.
     */
    public Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CAEntityNotInternalException, CANotFoundException,
            CertificateNotFoundException, CRLServiceException, InvalidCAException, InvalidEntityAttributeException {
        logger.debug("Retrieving all CRLs for the CA{} with certificate having certificateStatus{}", caEntityName, certificateStatus);
        final CAEntity caEntity = crlPersistenceHandler.getCAEntity(caEntityName);
        getValidCACertificates(caEntity, certificateStatus);
        Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap = null;
        try {
            crlInfoMap = crlManagerEServiceProxy.getCoreCRLManagementService().getAllCRLs(caEntityName, certificateStatus);

        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException e) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND + " for CA " + caEntityName, e);
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + " for CA " + caEntityName);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException e) {
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND + " for CA " + caEntityName + " with the certificateStatus " + certificateStatus, e);
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + " for CA " + caEntityName + " with the certificateStatus " + certificateStatus);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException | com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException e) {
            logger.error(ErrorMessages.INTERNAL_ERROR + " for getting all CRLs of CA " + caEntityName, e);
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR + " for getting all CRLs of CA " + caEntityName);
        }
        return crlInfoMap;
    }

    private List<Certificate> getValidCACertificates(final CAEntity caEntity, final CertificateStatus certStatus) throws CertificateNotFoundException {
        final List<Certificate> certList = CertificateAuthorityUtil.getCACertificatesByStatus(caEntity.getCertificateAuthority(), certStatus);
        if (certList.size() == 0) {
            logger.error("{} with the status {}", ErrorMessages.CERTIFICATE_NOT_FOUND, certStatus);
            systemRecorder.recordError("PKI_MANAGER_GET_VALID_CERTIFICATE.CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "CRLManager", "Get Valid Certificates", "Certificate not found for "
                    + caEntity.getCertificateAuthority().getName() + " with the status " + certStatus);
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + " with the status " + certStatus);
        }
        return certList;
    }

    /**
     * This method will get latest CRL for each ca certificate from pki-core. Fetched CRLs will be updated in the pki-manager data base.
     * 
     */
    public void deleteDuplicatesAndInsertLatestCRLs() {
        logger.debug("Inside deleteDuplicatesAndInsertLatestCRLs method in CRLManager");
        try {
            final List<CACertificateIdentifier> caCertificateIdentifierList = crlPersistenceHandler.getRequiredCACertIds();
            if (!caCertificateIdentifierList.isEmpty()) {
                final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet = crlManagerEServiceProxy.getCoreCRLManagementService().getLatestCRLs(caCertificateIdentifierList);
                logger.info("Retrieved all LATEST crl records.");
                crlPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifierList);
                logger.info("Deleted all duplicate crl records.");
                addOrUpdateLatestCRL(caCrlInfoHashMapToSet);
                logger.info("Updated LATEST crl information for duplicate records in pkimanager database.");
            } else {
                logger.info("No duplicate crl records found.");
            }
        } catch (final PersistenceException | com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException e) {
            logger.error(ErrorMessages.INTERNAL_ERROR + e.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR + e.getMessage(), e);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLManager", "Get CRL", "Internal error while fetching Latest CRLs from pkicore.");
        }
        logger.debug("End Of deleteDuplicatesAndInsertLatestCRLs method in CRLManager");
    }
}