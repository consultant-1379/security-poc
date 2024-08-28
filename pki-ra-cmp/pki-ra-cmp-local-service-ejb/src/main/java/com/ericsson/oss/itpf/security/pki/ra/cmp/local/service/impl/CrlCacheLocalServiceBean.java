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

package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPCrlCacheLocalService;

/**
 * This interface is used to update the CRL Map whenever a new file is created / modified in the existing Crl store.
 * 
 * @author xchowja
 */
@Stateless
public class CrlCacheLocalServiceBean implements CMPCrlCacheLocalService {

    @Inject
    CRLCacheUtil crlCacheUtil;

    @Inject
    Logger logger;

    @Override
    public void updateCrlCache(final String crlFileName) {
        if (crlCacheUtil != null) {
            crlCacheUtil.updateCache(crlFileName);
            logger.info("Successfully updated CRL cache for the file {}" , crlFileName);
        }
    }

    @Override
    public void initialiseCRLCache() {
        crlCacheUtil.initialiseCRLCache();
        logger.info("Successfully initialized CRL cache ");
    }
}
