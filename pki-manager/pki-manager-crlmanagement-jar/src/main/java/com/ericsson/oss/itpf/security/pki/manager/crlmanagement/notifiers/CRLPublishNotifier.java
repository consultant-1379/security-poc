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

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;

/**
 * This class is used for handling the Publish CRL to CDPS
 * 
 * @author xjagcho
 *
 */
public class CRLPublishNotifier {

    @Inject
    private CRLEventNotificationService crlEventNotificationService;

    @Inject
    private Logger logger;

    /**
     * This method handles the publish CRLs using list of CACertificateIdentifier
     * 
     * @param caCertificateIdentifiers
     *            it holds the list of CACertificateIdentifier it contains CAName and Certificate Serial Number
     */
    public void notify(final List<CACertificateIdentifier> caCertificateIdentifiers) {
        logger.debug("notify mtehod in CRLPublishNotifier class");
        if (!caCertificateIdentifiers.isEmpty()) {
            crlEventNotificationService.firePublishEvent(caCertificateIdentifiers);
        }
    }
}
