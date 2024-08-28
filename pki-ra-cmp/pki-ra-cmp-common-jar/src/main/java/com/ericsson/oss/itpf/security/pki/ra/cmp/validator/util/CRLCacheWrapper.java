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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util;

import javax.cache.Cache;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CRL;

/**
 * This class provides methods which are used for insert/update CRLs in the cache and retrieval of CRLs from the cache.
 * 
 * @author xbensar
 *
 */
@Singleton
public class CRLCacheWrapper {

    @Inject
    @NamedCache("CRLCache")
    private Cache<String, CRL> crlCache;

    @Inject
    Logger logger;

    /**
     * This method is used to insert the cache with the available CRLs, if the CRL is not available in the cache for the given issuer.Otherwise update CRLs in the cache if CRL is already available for
     * the given issuer.
     * 
     * @param issuerName
     *            Name of the issuer
     * @param crl
     *            object of CRL which contains CRL in encoded format.
     * 
     */
    @Lock(LockType.WRITE)
    public void insertOrUpdate(final String issuerName, final CRL crl) {
        if (crlCache.containsKey(issuerName)) {
            crlCache.replace(issuerName, crl);
            logger.info("crl is updated into cache for issuer : {} ", issuerName);
        } else {
            crlCache.putIfAbsent(issuerName, crl);
            logger.info("crl is inserted into cache for issuer :{} ", issuerName);
        }
    }

    /**
     * This method is used to retrieve crls from the cache using issuerName.
     * 
     * @param issuerName
     *            Name of the issuer
     * 
     */
    public CRL get(final String issuerName) {
        logger.info("GetCRL from cache for issuer : {}" , issuerName);
        return crlCache.get(issuerName);
    }

}
