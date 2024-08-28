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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper.CRLDownloader;
import com.ericsson.oss.itpf.security.pki.manager.exception.ExternalCredentialMgmtException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;

/**
 * Class used for importing and listing the certificates of CAEntities.
 *
 * <p>
 *
 * Listing of certificates, return the list of certificates of CAEntity based on certificate status.
 * </p>
 */

public class ExtCACRLManager {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Return the list of External CRL info of the External CA and all its associated CAs
     *
     * @param extCAName
     *            The External CA name.
     * @return List of ExternalCRLInfo objects.
     *
     * @throws ExternalCRLNotFoundException
     *             Throws in case of ExtCA hasn't CRLs.
     * @throws ExtCANotFoundException
     *             Thrown in case of given ExtCA does not exist.
     * @throws ExternalCRLEncodedException
     *             Thrown in case of any errors encoding the CRL.
     * @throws ExternalCredentialMgmtServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     */
    public List<ExternalCRLInfo> listExternalCRLInfo(final String extCAName) throws MissingMandatoryFieldException, ExternalCRLNotFoundException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, ExternalCRLEncodedException {
        logger.info("Getting the list of External CRL info of the External CA name {} ", extCAName);
        validateExtCAName(extCAName);

        try {
            final List<ExternalCRLInfo> crls = caPersistenceHelper.getExternalCRLInfoForExtCA(extCAName);
            if (crls == null) {
                logger.error(ErrorMessages.CRL_NOT_FOUND);
                throw new ExternalCRLNotFoundException(ErrorMessages.CRL_NOT_FOUND);
            }
            return crls;
        } catch (final ExternalCredentialMgmtException ex) {
            throw ex;
        } catch (final Exception exception) {
            logger.error("Exception while retrieving certificate", exception);
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR);
        }
    }

    /**
     * @param extCAName
     */
    private void validateExtCAName(final String extCAName) throws MissingMandatoryFieldException {
        if (extCAName == null || extCAName.isEmpty()) {
            logger.error(ErrorMessages.EXTERNAL_CA_NAME_EMPTY);
            throw new MissingMandatoryFieldException(ErrorMessages.EXTERNAL_CA_NAME_EMPTY);
        }
    }

    public void addCRL(final String extCAName, final ExternalCRLInfo crl) throws ExternalCANotFoundException, ExternalCRLException,ExternalCRLEncodedException, ExternalCredentialMgmtServiceException,
            MissingMandatoryFieldException {
        logger.info("Adding CRL with the ExternalCA Name {} and ExternalCRLInfo ", extCAName);
        try {
            validateExtCAName(extCAName);
            if (crl == null) {
                logger.error(ErrorMessages.EXTERNAL_CA_CRL_INFO_EMPTY);
                throw new MissingMandatoryFieldException(ErrorMessages.EXTERNAL_CA_CRL_INFO_EMPTY);
            }
            caPersistenceHelper.addCRL(extCAName, crl);
        } catch (final PersistenceException e) {
            throw new ExternalCredentialMgmtServiceException(e);
        }

    }

    public void configCRLInfo(final String extCAName, final Boolean isCrlAutoUpdateEnabled, final Integer crlAutoUpdateTimer) throws MissingMandatoryFieldException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException {
        logger.info("Configuring CRL info with ExternalCAName {} ", extCAName);
        try {
            validateExtCAName(extCAName);
            caPersistenceHelper.configCRLInfo(extCAName, isCrlAutoUpdateEnabled, crlAutoUpdateTimer);
        } catch (final PersistenceException e) {
            throw new ExternalCredentialMgmtServiceException(e);
        }
    }

    /**
     * @param extCAName
     */
    public void removeCRLs(final String extCAName, final String issuerName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLNotFoundException,
            ExternalCredentialMgmtServiceException {
        logger.info("Removing CRLs by using External CA name {} and Issuer name {} ", extCAName, issuerName);
        validateExtCAName(extCAName);

        try {
            final CAEntityData issuerCAEntityData = caPersistenceHelper.getCAEntity(extCAName);
            if (!(issuerCAEntityData.isExternalCA())) {
                logger.error(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
                throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
            }

            final Set<CAEntityData> associatedList = issuerCAEntityData.getAssociated();
            final List<ExternalCRLInfoData> crlDataList = new ArrayList<ExternalCRLInfoData>();

            boolean issuerNameFound = false;
            if (issuerName == null) {
                issuerNameFound = true;
                removeCRLForExternalCA(issuerCAEntityData, associatedList, crlDataList);
            } else {

                if ((issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData() != null) && (issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData().getCrl() != null)) {
                    X509CRLHolder x509CrlHolder;
                    try {
                        x509CrlHolder = new X509CRLHolder(issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData().getCrl());
                        if (issuerName.equals(x509CrlHolder.retrieveCRL().getIssuerDN().getName())) {

                            crlDataList.add(issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData());
                            issuerCAEntityData.getCertificateAuthorityData().setExternalCrlInfoData(null);
                            caPersistenceHelper.updateExtCA(issuerCAEntityData);
                            issuerNameFound = true;
                        }
                    } catch (final IOException | CRLException e) {
                        throw new ExternalCRLEncodedException("Problem with CRL Converter");
                    }
                }

                if (!issuerNameFound) {
                    for (final CAEntityData extca : associatedList) {
                        if ((extca.getCertificateAuthorityData().getExternalCrlInfoData() != null) && (extca.getCertificateAuthorityData().getExternalCrlInfoData().getCrl() != null)) {
                            X509CRLHolder x509CrlHolder;
                            try {
                                x509CrlHolder = new X509CRLHolder(extca.getCertificateAuthorityData().getExternalCrlInfoData().getCrl());
                                if (issuerName.equals(x509CrlHolder.retrieveCRL().getIssuerDN().getName())) {
                                    issuerNameFound = true;
                                    crlDataList.add(extca.getCertificateAuthorityData().getExternalCrlInfoData());
                                    associatedList.remove(extca);
                                    issuerCAEntityData.setAssociated(associatedList);
                                    caPersistenceHelper.updateExtCA(issuerCAEntityData);
                                    caPersistenceHelper.deleteExtCA(extca);
                                    break;
                                }
                            } catch (final IOException | CRLException e) {
                                throw new ExternalCRLEncodedException("Problem with CRL Converter");
                            }
                        }
                    }
                }
            }
            for (final ExternalCRLInfoData crl : crlDataList) {
                caPersistenceHelper.deleteExternalCRLInfo(crl);
            }
            if (!issuerNameFound) {
                logger.error(ErrorMessages.EXTERNAL_CA_ISSUER_NOT_FOUND);
                throw new ExternalCRLNotFoundException(ErrorMessages.EXTERNAL_CA_ISSUER_NOT_FOUND);
            }

        } catch (final PersistenceException  e) {
            logger.error("Exception occured while processing the request for removing CRLs");
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove CRLs", "Exception occured while processing the request for removing CRLs");
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR);
        } catch (final CANotFoundException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_NOT_FOUND_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove CRLs", ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
        }catch (final EntityServiceException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_NOT_FOUND_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove CRLs", ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            throw new ExternalCANotFoundException(ex);
        }
    }

    private void removeCRLForExternalCA(final CAEntityData issuerCAEntityData, final Set<CAEntityData> associatedList, final List<ExternalCRLInfoData> crlDataList)  throws PersistenceException{
        logger.info("Removing CRL for External CA with CA Entity Data");
        if (issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData() != null) {
            crlDataList.add(issuerCAEntityData.getCertificateAuthorityData().getExternalCrlInfoData());
        }

        for (final CAEntityData extca : associatedList) {
            if (extca.getCertificateAuthorityData().getExternalCrlInfoData() != null) {
                crlDataList.add(extca.getCertificateAuthorityData().getExternalCrlInfoData());
            }
        }

        issuerCAEntityData.setAssociated(null);
        issuerCAEntityData.getCertificateAuthorityData().setExternalCrlInfoData(null);

        caPersistenceHelper.updateExtCA(issuerCAEntityData);

        for (final CAEntityData associated : associatedList) {
            caPersistenceHelper.deleteExtCA(associated);
        }
    }

    /**
     * @param extCAName
     */
    public void removeAllCRLs(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCredentialMgmtServiceException {
        logger.info("Removing all CRLs by using External CA name {} ", extCAName);
        validateExtCAName(extCAName);

        try {
            final CAEntityData issuerCAEntityData = caPersistenceHelper.getCAEntity(extCAName);
            if (!(issuerCAEntityData.isExternalCA())) {
                logger.error(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_NAME_NOT_FOUND_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove all CRLs", ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
                throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
            }

            final List<String> trustProfiles = caPersistenceHelper.getTrustProfileNamesUsingExtCA(issuerCAEntityData);
            if (!trustProfiles.isEmpty()) {
                logger.error(ErrorMessages.EXTERNAL_CA_IS_USED);
                throw new ExternalCAInUseException(ErrorMessages.EXTERNAL_CA_IS_USED);
            }

            final Set<CAEntityData> associatedList = issuerCAEntityData.getAssociated();
            final List<ExternalCRLInfoData> crlDataList = new ArrayList<ExternalCRLInfoData>();

            removeCRLForExternalCA(issuerCAEntityData, associatedList, crlDataList);
            for (final ExternalCRLInfoData crl : crlDataList) {
                caPersistenceHelper.deleteExternalCRLInfo(crl);
            }

        } catch (final PersistenceException  e) {
            logger.error(ErrorMessages.INTERNAL_ERROR);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove all CRLs", ErrorMessages.INTERNAL_ERROR);
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, e);
        } catch (final CANotFoundException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_NOT_FOUND_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove all CRLs", ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND, ex);
        }catch (final EntityServiceException ex) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_NOT_FOUND_ERROR", ErrorSeverity.ERROR, "ExtCACRLManager", "Remove all CRLs", ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            throw new ExternalCANotFoundException(ex);
        }

    }

    /**
     * Retrieve all external CA with expired CRL and update them
     */
    public void autoUpdateExpiredCRLs() {
        List<ExternalCRLInfoData> externalCRLInfoData = null;
        try {
            externalCRLInfoData = caPersistenceHelper.getExpiredCRLs(new Date());
        } catch (final PersistenceException e) {
            systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.INTERNAL_ERRROR", "Exception while retrieving expired CRLs listr",
                    "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
            logger.debug("Unexpected Error in retrieving entities with Expired CRLs.", e);
            return;
        }
        for (final ExternalCRLInfoData extCRLinfo : externalCRLInfoData) {
            X509CRL x509CRL = null;
            final String urlName = extCRLinfo.getUpdateUrl();
            try {
                final URL url = new URL(urlName);
                x509CRL = CRLDownloader.getCRLFromURL(url);
                final X509CRLHolder x509CrlHolder = new X509CRLHolder(extCRLinfo.getCrl());
                final X500Name oldIssuerDN = new X500Name(x509CrlHolder.retrieveCRL().getIssuerDN().getName());
                final X500Name newIssuerDN = new X500Name(x509CRL.getIssuerDN().getName());
                if (newIssuerDN.equals(oldIssuerDN)) {
                    extCRLinfo.setCrl(x509CRL.getEncoded());
                    extCRLinfo.setNextUpdate(x509CRL.getNextUpdate());
                    caPersistenceHelper.setExpiredCRLs(extCRLinfo);
                } else {
                    systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.MISMATCH", "Stored CRL Issuer doesn't match with new CRL Issuer",
                            "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
                }
            } catch (final CRLException e1) {
                systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.PARSING", "CRL retrived from " + urlName + " can't be parsed",
                        "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
                logger.debug(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA, e1);
            } catch (final MalformedURLException e) {
                systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.MALFORMEDURL", "The CRL " + urlName + " is marlformed",
                        "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
            } catch (final PersistenceException e) {
                systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.INTERNAL_ERRROR", "Error updating CRL (externalcrlinfo id=" + extCRLinfo.getId() + ")",
                        "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
                logger.debug("Error while updating CRL ", e);
            } catch (final IOException e) {
                systemRecorder.recordSecurityEvent("PKIMANAGER-CRLMANAGEMENT", "PKIMANAGER-CRLMANAGEMENT.INTERNAL_ERRROR", "Error storing CRL (externalcrlinfo id=" + extCRLinfo.getId() + ")",
                        "PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE", ErrorSeverity.CRITICAL, "FAILURE");
                logger.debug("Error while storing CRL ", e);
            }
        }
    }
}
