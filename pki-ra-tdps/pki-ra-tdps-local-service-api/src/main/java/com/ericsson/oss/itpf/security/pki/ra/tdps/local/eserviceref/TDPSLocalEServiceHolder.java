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
package com.ericsson.oss.itpf.security.pki.ra.tdps.local.eserviceref;

import javax.ejb.Stateless;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.api.TDPSLocalService;

/**
 * This class contains the services referenced using EServiceRef and has getters for each of these. The classes that need these services should use the getters instead of directly injecting them using
 * EServiceRef
 * 
 */
@Stateless
public class TDPSLocalEServiceHolder {

    @EServiceRef
    TDPSLocalService tdpsLocalService;

    /**
     * This method returns the TDPSLocalService
     * 
     */
    public TDPSLocalService getTDPSLocalService() {

        return tdpsLocalService;
    }

}
