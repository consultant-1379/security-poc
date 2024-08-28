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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.handler;

import java.util.List;


import javax.ejb.EJB;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

/**
 * CRLNotificationRequestMessageHandler class will handle the publish and unpublish request
 * 
 * @author xvambur
 * 
 */
public class CRLNotificationRequestMessageHandler {

    @Inject
    private Logger logger;

    @Inject
    CRLEventNotificationService crlEventNotificationService;

    @EJB
    public CRLManagementLocalService crlManagementLocalService;

    /**
     * This method is used handle all eligible CRLs for Publishing and UnPublishing to CDPS.
     * 
     */
    public void handle() {
        logger.debug("handle method in CRLNotificationRequestMessageHandler class");
        publishLatestCRLs();
        unpublishCRLs();
    }

    private void publishLatestCRLs() {
        logger.debug("publish latest CRLs");
        try {
            final List<CACertificateIdentifier> caCertificateIdentifierList = crlManagementLocalService.getAllPublishCRLs();
            crlEventNotificationService.firePublishEvent(caCertificateIdentifierList);
        } catch (Exception exception) {
            handleException(exception);
        }
    }

    private void unpublishCRLs() {
        logger.debug("unpublish latest CRLs");
        try {
            final List<CACertificateIdentifier> caCertificateIdentifierList = crlManagementLocalService.getAllUnPublishCRLs();
            crlEventNotificationService.fireUnpublishEvent(caCertificateIdentifierList);
        } catch (Exception exception) {
            handleException(exception);
        }
    }

    private void handleException(final Throwable cause) {
        logger.debug("Exception StackTrace: ", cause);
        logger.warn("Error Occured while retriving CRL's ");
    }
}
