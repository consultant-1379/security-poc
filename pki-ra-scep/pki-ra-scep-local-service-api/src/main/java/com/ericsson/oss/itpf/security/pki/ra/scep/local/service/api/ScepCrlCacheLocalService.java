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
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;

/**
 * This interface is used to update the CRL Cache
 * 
 * @author xramdag
 * 
 */
@EService
@Local
public interface ScepCrlCacheLocalService {

    /**
     * This method will update existing CRL cache for modified/new CRL file name.
     * 
     * @param crlFileName
     *            for which CRL cache will be update.
     */
    void updateCrlCache(final String crlFileName);

}
