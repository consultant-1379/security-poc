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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers;

import java.security.cert.CertificateEncodingException;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.TDPSEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class is used for handling the UnPublish certificate events and notifies to TDPS.
 * 
 * @author tcsnavg
 *
 */
public class TDPSUnpublishNotifier {

    @Inject
    TDPSEventNotificationService tDPSEventNotificationService;

    @Inject
    Logger logger;

    /**
     * This is a notifier method which fires TDPSUnpublish event those are revoked.
     * 
     * @param entityType
     *            entity type CA/End Entity
     * @param entityName
     *            name of the CA/End entity
     * @param certificates
     *            it holds the list of certificates based on entityName, entityType, tdpsPublishStatusType
     * @throws CertificateEncodingException
     *             thrown whenever an error occurs while attempting to encode a certificate.
     */
    public void notify(final EntityType entityType, final String entityName, final List<Certificate> certificates) throws CertificateEncodingException {
        logger.debug("Firing TDPS unpublish event");
        tDPSEventNotificationService.fireCertificateEvent(entityType, entityName, TDPSPublishStatusType.UNPUBLISH, certificates);
    }
}
