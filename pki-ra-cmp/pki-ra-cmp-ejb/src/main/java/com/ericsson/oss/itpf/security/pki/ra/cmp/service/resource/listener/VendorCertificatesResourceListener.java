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
 * This listener will listen Vendor Certificates resource directory path location. When RA service is running, if there is any modification in existing Vendor Certificates (External trusts) or if any
 * new External trusts are added then listener will re-initialize Vendor certificates(External Trusts).
 *
 * @author tcsmanp
 */
public class VendorCertificatesResourceListener implements FileResourceListener {

    private final String vendorCertificatesURI;
    private final FileResourceEventType[] vendorCertificatesEventTypes;
    private final Logger logger = LoggerFactory.getLogger(VendorCertificatesResourceListener.class);
    private final ServiceFinderBean serviceFinder = new ServiceFinderBean();

    public VendorCertificatesResourceListener(final String vendorCertificatesURI, final FileResourceEventType[] vendorCertificatesEventTypes) {
        this.vendorCertificatesURI = vendorCertificatesURI;
        this.vendorCertificatesEventTypes = vendorCertificatesEventTypes;
    }

    @Override
    public void onEvent(final FileResourceEvent fileResourceEvent) {
        try {
            final CmpCertificatesLocalService cmpCertificatesLocalService = serviceFinder.find(CmpCertificatesLocalService.class);
            cmpCertificatesLocalService.initializeVendorCertificates();
            logger.info("Successfully re-initialized Vendor certificates(External Trusts)");
        } catch (final Exception exception) {
            logger.error(ErrorMessages.FAILED_TO_INITIALIZE_VENDOR_CERTIFICATES, exception.getMessage());
            logger.debug("Exception occurred while initializing Vendor Certificates ", exception);
        }
    }

    @Override
    public String getURI() {
        return vendorCertificatesURI;
    }

    @Override
    public FileResourceEventType[] getEventTypes() {
        return vendorCertificatesEventTypes;
    }
}
