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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * This class is used for handling the all the UnPublish CRL scenarios like UnPblish CRL For RevokedCACertificate,ExpiredCACertificate and UnPublish
 *
 * @author xjagcho
 *
 */
public class CRLUnpublishNotifier {

    @Inject
    private CRLEventNotificationService crlEventNotificationService;

    @Inject
    private CRLHelper crlHelper;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private Logger logger;

    /**
     * This Method handles the UnPublish CRL related operations
     *
     * @param caCertificateIdentifiers
     *            it contains the CACertificateIdentifier it holds CAName and Certificate Serial Number
     *
     * @param unpublishType
     *            it holds the revoked_expired_ca_certificate ,crl_not_required_in_cdps
     */
    public void notify(final List<CACertificateIdentifier> caCertificateIdentifiers, final CRLUnpublishType crlUnpublishType) {
        logger.info("notify method in CRLUnpublishNotifier class");

        switch (crlUnpublishType) {
        case EXPIRED_CA_CERTIFICATE:
            final List<CACertificateIdentifier> unpublishedCACertificateIdentifiers = getUnpublishCACertificateIdentifiers(caCertificateIdentifiers);
            if (!unpublishedCACertificateIdentifiers.isEmpty()) {
                crlEventNotificationService.fireUnpublishEvent(unpublishedCACertificateIdentifiers, crlUnpublishType);
            }
            break;
        case REVOKED_CA_CERTIFICATE:
            final List<CACertificateIdentifier> unpublishedRevokedCACertificateIdentifiers = getUnpublishRevokedCACertificateIdentifiers();
            if (!unpublishedRevokedCACertificateIdentifiers.isEmpty()) {
                crlEventNotificationService.fireUnpublishEvent(unpublishedRevokedCACertificateIdentifiers, crlUnpublishType);
            }
            break;

        case USER_INVOKED_REQUEST:
        case CRL_EXPIRED:
            crlEventNotificationService.fireUnpublishEvent(caCertificateIdentifiers);
            break;

        default:
            logger.error("Unsupported Unpublish Type {} ", crlUnpublishType);
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS",
                    "Unblish CRL event failed due to Unsupported Unpublish Type: " + crlUnpublishType);
        }
        logger.info("End of notify method in CRLUnpublishNotifier class");
    }

    private List<CACertificateIdentifier> getUnpublishCACertificateIdentifiers(final List<CACertificateIdentifier> caCertificateIdentifiers){
        logger.info("getUnpublishCACertificateIdentifiers method in CRLUnpublishNotifier class ");
        final List<CACertificateIdentifier> unpublishCACertificateIdentifiers = new ArrayList<CACertificateIdentifier>();

        for (final CACertificateIdentifier caCertificateIdentifier : caCertificateIdentifiers) {
            CRLInfo crlInfo = new CRLInfo();
            try {
                crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, false, false);
            } catch (final CANotFoundException | CertificateNotFoundException | CRLNotFoundException | CRLServiceException exception) {
                logger.debug("Unable to get CRL to unpublish ", exception);
                logger.error("Unable to get CRL to unpublish for {} , {}", caCertificateIdentifier, exception.getMessage());
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS", "Unable to get CRL to unpublish for "
                        + caCertificateIdentifier);
            }
            if (crlInfo.isPublishedToCDPS()) {
                unpublishCACertificateIdentifiers.add(caCertificateIdentifier);
            } else {
                try {
                    crlInfo.setStatus(CRLStatus.INVALID);
                    crlHelper.updateCRLStatus(crlInfo);
                } catch (final CANotFoundException | CertificateNotFoundException | CRLNotFoundException | CRLServiceException | ExpiredCertificateException | RevokedCertificateException exception) {
                    logger.debug("Unable to update CRL from DB ", exception);
                    logger.error("Unable to update CRL from DB for {}", caCertificateIdentifier);
                    systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS", "Unable to update CRL from DB for "
                            + caCertificateIdentifier);
                }
            }
        }
        logger.info("End of getUnpublishCACertificateIdentifiers method in CRLUnpublishNotifier class ");
        return unpublishCACertificateIdentifiers;
    }

    private List<CACertificateIdentifier> getUnpublishRevokedCACertificateIdentifiers() {
        final List<CACertificateIdentifier> caCertIdsToUnpublishCRL = new ArrayList<CACertificateIdentifier>();
        final List<CACertificateIdentifier> caCertIdsToDeleteCRLs = new ArrayList<CACertificateIdentifier>();
        List<CRLInfo> crlInfos = new ArrayList<CRLInfo>();
        CACertificateIdentifier caCertificateIdentifier = null;
        try {
            crlInfos = crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST);
        } catch (final CRLServiceException crlServiceException) {
            logger.debug("Unable to get CRL from DB ", crlServiceException);
            logger.error("Unable to get CRL from DB {} ", crlServiceException.getMessage());
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS", "Unable to get CRL from DB");
        }
        if (!ValidationUtils.isNullOrEmpty(crlInfos)) {
            for (CRLInfo crlInfo : crlInfos) {
                try {
                    crlHelper.validateCertificateChain(crlInfo.getIssuerCertificate());
                } catch (final ExpiredCertificateException | RevokedCertificateException exception) {
                    final String caName = crlHelper.getCANameByCRL(crlInfo.getId());
                    caCertificateIdentifier = new CACertificateIdentifier(caName, crlInfo.getIssuerCertificate().getSerialNumber());
                    logger.debug("CRL chain validation is failed for the CA certificate ", exception);
                    logger.error("CRL chain validation is failed for the CA certificate {}, {}", caCertificateIdentifier, exception.getMessage());
                    systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS", "CRL chain validation is failed");
                    if (crlInfo.isPublishedToCDPS()) {
                        caCertIdsToUnpublishCRL.add(caCertificateIdentifier);
                    } else {
                        caCertIdsToDeleteCRLs.add(caCertificateIdentifier);
                    }
                }
            }
        }
        if (!caCertIdsToDeleteCRLs.isEmpty()) {
            try {
                crlHelper.deleteInvalidCRLs(caCertIdsToDeleteCRLs);
                logger.info("Invalid CRL deleted from data base for {}", caCertificateIdentifier);
            } catch (final CANotFoundException | ExpiredCertificateException | RevokedCertificateException | CertificateNotFoundException | CRLNotFoundException | CRLServiceException e) {
                logger.debug("Unable to delete CRL from DB for the CA certificate ", e);
                logger.error("Unable to delete CRL from DB for the CA certificate {}", caCertificateIdentifier);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.UNPUBLISH_CRLS", ErrorSeverity.ERROR, "CRLUnpublishNotifier", "Unpublish CRL From CDPS",
                        "Unable to delete CRL from DB for the CA certificate " + caCertificateIdentifier);
            }
        }
        return caCertIdsToUnpublishCRL;
    }
}