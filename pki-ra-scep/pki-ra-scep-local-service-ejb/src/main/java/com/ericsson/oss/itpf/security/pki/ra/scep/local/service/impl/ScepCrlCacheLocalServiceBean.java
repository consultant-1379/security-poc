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
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.impl;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.ScepCrlCacheLocalService;

/**
 * This class is used to update the SCEP Crl Cache.
 * 
 * @author xramdag
 * 
 */
@Stateless
public class ScepCrlCacheLocalServiceBean implements ScepCrlCacheLocalService {

    @Inject
    private ScepCrlCacheUtil scepCrlCacheUtil;

    @Inject
    private Logger logger;

    /**
     * This method will update existing CRL cache for modified/new CRL file name.
     * 
     * @param crlFileName
     *            for which CRL cache will be update.
     */
    @Override
    public void updateCrlCache(final String crlFileName) {
        logger.debug("Inside updateCrlCache method of ScepCrlCacheLocalServiceBean class:");
        if (scepCrlCacheUtil != null) {
            scepCrlCacheUtil.updateCache(crlFileName);
        }
        logger.debug("End of updateCrlCache method in ScepCrlCacheLocalServiceBean class:");

    }

}
