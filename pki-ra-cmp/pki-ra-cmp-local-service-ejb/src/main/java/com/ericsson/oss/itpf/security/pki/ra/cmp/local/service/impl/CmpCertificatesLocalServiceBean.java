/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CmpCertificatesLocalService;

/**
 * This class is used to update the Vendor trust store and CA trust store for modified/new file.
 *
 * @author xvadyas
 *
 */
@Stateless
public class CmpCertificatesLocalServiceBean implements CmpCertificatesLocalService {

    @Inject
    InitialConfiguration initialConfiguration;

    @Inject
    Logger logger;

    /**
     * This method will reinitialize the existing Vendor trust store whenever a new file is created / modified in the existing Vendor trust store.
     */
    @Override
    public void initializeVendorCertificates() {
        if (initialConfiguration != null) {
            initialConfiguration.reInitializeVendorCertificates();
            logger.info("Successfully updated Vendor Certificates for the file ");
        }
    }

    /**
     * This method will reinitialize the existing CA trust store whenever a new file is created / modified in the existing CA trust store.
     */
    @Override
    public void initializeCaCertificates() {
        if (initialConfiguration != null) {
            initialConfiguration.reInitializeCACertificates();
            logger.info("Successfully updated CA Certificates for the file ");
        }
    }
}
