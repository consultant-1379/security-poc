/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.InvalidAlgorithmTypeException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * 
 * This interface provides methods to perform the cache insert and update operations for SuppotedAlgorithmCache
 * 
 * @author tcsvsai
 *
 */

@EService
@Local
public interface SupportedAlgorithmsCacheOperations {

    /**
     * This method is used to load all the Supported Algorithms into the cache. The cache is a key-object pair. The key of the cache is the
     * SupportedAlgorithmType and value of cache is the list of OIDs corresponding to that Algorithm Type.
     *
     * @throws InvalidAlgorithmTypeException
     *             thrown when there is an unsupported/invalid algorithm type in the algorithms being loaded
     */
    void load() throws InvalidAlgorithmTypeException;

    /**
     * This method is used to update SupportedAlgorithmCache for the Algorithm that is passed
     * 
     * @param updateAlgorithmData
     *            is the algorithm data whose oid need to be updated in the cache
     */
    void update(final AlgorithmData updateAlgorithmData);
}
