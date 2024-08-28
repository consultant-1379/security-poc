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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

/**
 * This is a local ejb class for CRLManagementService. It is used to provide new transaction if a request is not associated with any transaction.
 * 
 * @author xramdag
 */
@Stateless
public class CRLManagementLocalServiceBean implements CRLManagementLocalService {

    @Inject
    private CRLHelper crlHelper;

    @Inject
    private Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    @Override
    public void updateCRLPublishUnpublishStatus(final List<CACertificateIdentifier> caCertificateIdentifiers, final boolean isPublishedToCDPS) {
        logger.debug("updateCRLStatus Method in CRLManagementLocalServiceBean class");
        final String status = (isPublishedToCDPS) ? "Published" : "Unpublished";
        for (CACertificateIdentifier caCertificateIdentifier : caCertificateIdentifiers) {
            try {
                final CRLInfo crlInfo = crlHelper.getCRLByCACertificate(caCertificateIdentifier, false, false);
                crlInfo.setPublishedToCDPS(isPublishedToCDPS);
                crlHelper.updateCRLStatus(crlInfo);
                logger.info("CRL have been {} successfully for the {}", status, caCertificateIdentifier);
            } catch (CANotFoundException | CertificateNotFoundException | CRLNotFoundException | CRLServiceException | ExpiredCertificateException | RevokedCertificateException exception) {
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLManagementLocalServiceBean", "Update CRL status", "Unable to update the CRL status to "
                        + status + " for the CRL issued by " + caCertificateIdentifier + " due to " + exception.getMessage());
                logger.error("Unable to update the CRL status to {} for the CRL issued by {} due to {}", status, caCertificateIdentifier, exception.getMessage());
                logger.debug("Unable to update the CRL status to {} for the CRL issued by {} due to {}", status, caCertificateIdentifier, exception);
            }
        }
        logger.debug("End of updateCRLStatus Method in CRLManagementLocalServiceBean class");
    }

    @Override
    public void deleteInvalidCRLs(final List<CACertificateIdentifier> caCertificateIdentifiers) {
        logger.debug("deleteInvalidCRLs Method in CRLManagementLocalServiceBean class");
        crlHelper.deleteInvalidCRLs(caCertificateIdentifiers);
    }

    @Override
    public CRLInfo getCRLByCACertificateIdentifier(final CACertificateIdentifier caCertificateIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException,
            CRLServiceException, ExpiredCertificateException, RevokedCertificateException {
        logger.debug("getCRLByCACertificateIdentifier Method in CRLManagementLocalServiceBean class");

        return crlHelper.getCRLByCACertificate(caCertificateIdentifier, false, false);
    }

    @Override
    public List<CACertificateIdentifier> getAllPublishCRLs() throws CRLServiceException {
        final List<CACertificateIdentifier> caCertificateIdentifierList = crlHelper.getCRLsForPublishOnStartup();
        return caCertificateIdentifierList;
    }

    @Override
    public List<CACertificateIdentifier> getAllUnPublishCRLs() throws CRLServiceException {

        final List<CACertificateIdentifier> caCertificateIdentifierList = crlHelper.getCRLsForUnpublishOnStartup();
        return caCertificateIdentifierList;
    }
}