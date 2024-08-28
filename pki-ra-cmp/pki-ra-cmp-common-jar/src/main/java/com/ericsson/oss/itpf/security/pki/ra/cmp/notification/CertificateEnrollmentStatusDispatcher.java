/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class sends certificateEnrollmentStatus onto modeled event bus.
 *
 * @author xgvgvgv
 *
 */
public class CertificateEnrollmentStatusDispatcher {

    @Inject
    @Modeled
    private EventSender<CertificateEnrollmentStatus> certificateEnrollmentSender;

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateEnrollmentStatusDispatcher.class);

    /**
     * This method sends certificateEnrollmentStatus over the modeled event bus
     * 
     * @param certificateEnrollmentStatus
     *            The certificate enrollment status event which has to be sent to AP.
     */
    public void dispatch(final CertificateEnrollmentStatus certificateEnrollmentStatus) {

        try {
            LOGGER.info("Sending certificate enrollment status event to the corresponding service. The event contains [{}]", certificateEnrollmentStatus);
            certificateEnrollmentSender.send(certificateEnrollmentStatus);
        } catch (Exception e) {
            LOGGER.error("Error while sending certificate enrollment status", e);
        }

    }
}
