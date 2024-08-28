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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Lock;

import javax.cache.Cache;
import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cache.annotation.NamedCache;
import com.ericsson.oss.itpf.sdk.cluster.lock.LockManager;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.helper.AlgorithmLoader;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.InvalidAlgorithmTypeException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SupportedAlgorithmsCacheOperations;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * 
 * This bean provides implementation for SupportAlgorithmsCacheOperations to perform the cache insert and update operations for SupportedAlgorithmCache.
 * 
 * @author tcssarb
 *
 */

@Stateless
public class SupportedAlgorithmsCacheOperationsBean implements SupportedAlgorithmsCacheOperations{

    private static final String SUPPORTED_ALGORITHMS_CACHE_LOCK = "SupportedAlgorithmsCacheLock";

    @Inject
    private Logger logger;

    @Inject
    AlgorithmLoader algorithmLoader;

    @Inject
    @NamedCache("SupportedAlgorithmsCache")
    private Cache<String, List<String>> cache;

    @Inject
    private LockManager supportedAlgorithmsCacheLockManager;

    @Override
    public void load() throws InvalidAlgorithmTypeException {
        logger.info("Entering loadSupportedAlgorithms method in SupportAlgorithmsCacheOperationsBean");

        final List<String> symmetricAlgList = new ArrayList<>();

        final List<String> signatureAlgList = new ArrayList<>();

        final List<String> messageDigestAlgList = new ArrayList<>();

        final List<String> assymetricAlgList = new ArrayList<>();

        List<Algorithm> listOfAlgData = null;

        listOfAlgData = algorithmLoader.getSupportedAlgorithmsByType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM, AlgorithmType.MESSAGE_DIGEST_ALGORITHM, AlgorithmType.SIGNATURE_ALGORITHM,
                AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        for (final Algorithm algData : listOfAlgData) {

            switch (algData.getType()) {
            case SYMMETRIC_KEY_ALGORITHM:
                symmetricAlgList.add(algData.getOid());
                break;

            case SIGNATURE_ALGORITHM:
                signatureAlgList.add(algData.getOid());
                break;

            case MESSAGE_DIGEST_ALGORITHM:
                messageDigestAlgList.add(algData.getOid());
                break;

            case ASYMMETRIC_KEY_ALGORITHM:
                assymetricAlgList.add(algData.getOid());
                break;

            default:
                logger.info("Algortithm type is not required/invalid");
                throw new InvalidAlgorithmTypeException("Invalid Algorithm Type");
            }
        }
        try {
            getSupportedAlgorithmsCacheLock().lock();
            logger.info("Acquired the Distributed Lock {}",SUPPORTED_ALGORITHMS_CACHE_LOCK);
            cache.putIfAbsent(AlgorithmType.SYMMETRIC_KEY_ALGORITHM.value(), symmetricAlgList);
            cache.putIfAbsent(AlgorithmType.SIGNATURE_ALGORITHM.value(), signatureAlgList);
            cache.putIfAbsent(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value(), messageDigestAlgList);
            cache.putIfAbsent(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value(), assymetricAlgList);
            logger.info("End of loadSupportedAlgorithms method in SupportAlgorithmsCacheOperationsBean");
        } finally {
            getSupportedAlgorithmsCacheLock().unlock();
            logger.info("Released the Distributed Lock {}",SUPPORTED_ALGORITHMS_CACHE_LOCK);
        }
    }

    @Override
    public void update(final AlgorithmData updateAlgorithmData) {
        logger.info("Entering of updateSupportedAlgCache method in SupportAlgorithmsCacheOperationsBean");

        List<String> symmetricAlgList = null;
        List<String> signatureAlgList = null;
        List<String> messageDigestAlgList = null;
        List<String> assymetricAlgList = null;

        switch (AlgorithmType.getType(updateAlgorithmData.getType())) {
        case SYMMETRIC_KEY_ALGORITHM:
            symmetricAlgList = cache.get((AlgorithmType.SYMMETRIC_KEY_ALGORITHM.value()));
            updatedAlgorithmList(symmetricAlgList, updateAlgorithmData);
            cache.put(AlgorithmType.SYMMETRIC_KEY_ALGORITHM.value(), symmetricAlgList);
            break;
        case SIGNATURE_ALGORITHM:
            signatureAlgList = cache.get((AlgorithmType.SIGNATURE_ALGORITHM.value()));
            updatedAlgorithmList(signatureAlgList, updateAlgorithmData);
            cache.put(AlgorithmType.SIGNATURE_ALGORITHM.value(), signatureAlgList);
            break;
        case MESSAGE_DIGEST_ALGORITHM:
            messageDigestAlgList = cache.get((AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value()));
            updatedAlgorithmList(messageDigestAlgList, updateAlgorithmData);
            cache.put(AlgorithmType.MESSAGE_DIGEST_ALGORITHM.value(), messageDigestAlgList);
            break;
        case ASYMMETRIC_KEY_ALGORITHM:
            assymetricAlgList = cache.get((AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value()));
            updatedAlgorithmList(assymetricAlgList, updateAlgorithmData);
            cache.put(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.value(), assymetricAlgList);
            break;
        default:
            logger.info("Algortithm type is not required/invalid");
            break;
        }
        logger.info("End of updateSupportedAlgCache method in SupportAlgorithmsCacheOperationsBean");
    }

    /**
     * This method will add algorithm to the list in the cache when the algorithm is supported and will remove when the algorithm is not supported.
     * 
     * @param algorithmList
     *            is the algorithmList present in the cache.
     * @param algorithmData
     *            is the algorithm data whose oid need to be updated in the cache.
     * @param algorithm
     *            is the list of algorithms which are updated in the PKI Manager Database.
     */
    private void updatedAlgorithmList(final List<String> algorithmList, final AlgorithmData algorithmData) {
        logger.info("Entering updatedAlgorithmList method in SupportAlgorithmsCacheOperationsBean");
        if (algorithmData.isSupported()) {
            if (!algorithmList.contains(algorithmData.getOid())) {
                algorithmList.add(algorithmData.getOid());
            }
        } else {
            if (algorithmList.contains(algorithmData.getOid())) {
                algorithmList.remove(algorithmData.getOid());
            }
        }
        logger.info("End of updatedAlgorithmList method in SupportAlgorithmsCacheOperationsBean");
    }

    private Lock getSupportedAlgorithmsCacheLock() {
        return supportedAlgorithmsCacheLockManager.getDistributedLock(SUPPORTED_ALGORITHMS_CACHE_LOCK);
    }
}
