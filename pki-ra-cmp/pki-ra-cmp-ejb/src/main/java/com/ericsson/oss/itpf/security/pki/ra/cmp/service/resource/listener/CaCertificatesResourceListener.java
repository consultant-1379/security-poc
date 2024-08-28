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

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEvent;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEventType;
import com.ericsson.oss.itpf.sdk.resources.file.listener.FileResourceListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CmpCertificatesLocalService;

/**
 * This listener will listen CA Certificates resource directory path location. When RA service in running, if there any modification in existing CA Certificates (Internal trusts) or any new Internal
 * trusts are added then listener will re re-initialize CA certificates(Internal Trusts).
 *
 * @author tcsmanp
 */

public class CaCertificatesResourceListener implements FileResourceListener {

    private final String caCertificatesURI;
    private final FileResourceEventType[] caCertificatesEventTypes;
    private final Logger logger = LoggerFactory.getLogger(CaCertificatesResourceListener.class);
    private final ServiceFinderBean serviceFinder = new ServiceFinderBean();

    public CaCertificatesResourceListener(final String caCertificatesURI, final FileResourceEventType[] caCertificatesEventTypes) {
        this.caCertificatesURI = caCertificatesURI;
        this.caCertificatesEventTypes = caCertificatesEventTypes;
    }

    @Override
    public void onEvent(final FileResourceEvent fileResourceEvent) {
        try {
            final CmpCertificatesLocalService cmpCertificatesLocalService = serviceFinder.find(CmpCertificatesLocalService.class);
            cmpCertificatesLocalService.initializeCaCertificates();
            logger.info("Successfully re-initialized CA certificates(Internal Trusts)");
        } catch (final Exception exception) {
            logger.error(ErrorMessages.FAILED_TO_INITIALIZE_CA_CERTIFICATES, exception.getMessage());
            logger.debug("Exception occurred while initializing CA Certificates ", exception);
        }
    }

    @Override
    public String getURI() {
        return caCertificatesURI;
    }

    @Override
    public FileResourceEventType[] getEventTypes() {
        return caCertificatesEventTypes;
    }
}
