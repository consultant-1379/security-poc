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
package com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util;

import javax.cache.Cache;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.security.pkira.scep.cdt.ScepCrl;

/**
 * This class provides methods which are used for insert/update CRLs in the cache and retrieval of CRLs from the cache.
 * 
 * @author xramdag
 *
 */
@Singleton
public class ScepCrlCacheWrapper {

    @Inject
    @NamedCache("ScepCrlCache")
    private Cache<String, ScepCrl> scepCrlCache;

    @Inject
    Logger logger;

    /**
     * This method is used to insert the cache with the available CRLs, if the CRL is not available in the cache for the given issuer.Otherwise update CRLs in the cache if CRL is already available for
     * the given issuer.
     * 
     * @param issuerName
     *            Name of the issuer
     * @param scepCrl
     *            object of ScepCrl which contains CRL in encoded format.
     * 
     */
    @Lock(LockType.WRITE)
    public void insertOrUpdate(final String issuerName, final ScepCrl scepCrl) {
        if (scepCrlCache.containsKey(issuerName)) {
            scepCrlCache.replace(issuerName, scepCrl);
            logger.info("crl is updated in the cache for issuer {} ", issuerName);
        } else {
            scepCrlCache.putIfAbsent(issuerName, scepCrl);
            logger.info("crl is inserted into cache for issuer {} ", issuerName);
        }
    }

    /**
     * This method is used to retrieve crls from the cache using issuerName.
     * 
     * @param issuerName
     *            Name of the issuer
     * 
     */
    @Lock(LockType.READ)
    public ScepCrl get(final String issuerName) {
        logger.info("GetCRL from cache for issuer {} ", issuerName);
        return scepCrlCache.get(issuerName);
    }

}
