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
package com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;

/**
 * This class acts as a holder for all EServices
 * @author zmasshr
 *
 */
@ApplicationScoped
public class KeyAccessProviderServiceProxy {

    @EServiceRef
    private KeyAccessProviderService keyAccessProviderService;

    /**
     * returns KeyAccessProviderService
     */
    public KeyAccessProviderService getKeyAccessProviderService() {
        return keyAccessProviderService;
    }

}
