/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.util;

import javax.cache.Cache;
import javax.ejb.*;

import com.ericsson.oss.itpf.sdk.cache.classic.CacheProviderBean;

/**
 * Class that provide support to keep the file to be downloaded in cache. This
 * instance is made singleton to make only one copy of it in system.
 * 
 * @author xsumnan
 * 
 */
@Singleton
public class ExportedItemsHolder {

    final CacheProviderBean bean = new CacheProviderBean();
    final Cache<String, Object> cache = bean.createOrGetModeledCache("PkiWebCliExportCache");

    public Cache<String, Object> getCache() {
        return cache;
    }
    
    @Lock(LockType.WRITE)
    public void save(final String key, final Object instance) {
        cache.put(key, instance);
    }

    public Object fetch(final String key) {
        return cache.get(key);
    }
    
    @Lock(LockType.WRITE)
    public Object remove(final String key) {
        return cache.remove(key);
    }

}
