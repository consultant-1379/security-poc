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
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;

/**
 * This interface is used to update the Vendor trust store and CA trust store.
 *
 * @author xvadyas
 *
 */
@EService
@Local
public interface CmpCertificatesLocalService {

    /**
     * This method will initialize the Vendor trust store whenever CMP service is up and running. Also it will reinitialize whenever the new file creation/modification in the existing Vendor trust
     * store.
     */
    void initializeVendorCertificates();

    /**
     * This method will initialize the CA trust store whenever CMP service is up and running. Also it will reinitialize whenever the new file creation/modification in the existing CA trust store.
     */
    void initializeCaCertificates();
}
