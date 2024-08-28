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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier;

import java.security.cert.CertificateEncodingException;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.TDPSEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class is Notifier class which will fire a TDPSNotification to tdps-certificate-event-handler. This handler module will eventually fire modeleed event to pki-ra-tdps
 * 
 * @author tcsdemi
 *
 */
public class CertificateEventNotifier {

    @Inject
    TDPSEventNotificationService tDPSEventNotificationService;

    @Inject
    Logger logger;

    /**
     * This is a notifier method which will fire tdps notification.
     * 
     * @param certificateEventNotification
     * @throws CertificateEncodingException
     */
    public void notify(final EntityType entityType, final String entityName, final TDPSPublishStatusType tDPSPublishStatusType, final List<Certificate> certificates)
            throws CertificateEncodingException {
        logger.debug("Firing TDPS publish event");
        tDPSEventNotificationService.fireCertificateEvent(entityType, entityName, tDPSPublishStatusType, certificates);
    }
}
