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

package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util;

import java.util.List;

import javax.cache.Cache;
import javax.ejb.Singleton;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;

/**
 * This class provides get method to retrieve data from SupportedAlgorithmCache.
 *
 * @author 1210241
 */
@Singleton
public class SupportedAlgorithmsCacheWrapper {

    @Inject
    private Logger logger;

    @Inject
    @NamedCache("SupportedAlgorithmsCache")
    private Cache<String, List<String>> supportedAlgorithmsCache;

    /**
     * This method is used to retrieve supported algorithms from the cache using
     * the key algorithmType.
     *
     * @param algorithmType
     *            key String to retrieve data from cache.
     * @return List of String values
     */
    public List<String> get(final String algorithmType) {
        logger.info("Get Support Algorithms from cache for algorithm type {}", algorithmType);
        return supportedAlgorithmsCache.get(algorithmType);
    }

}
