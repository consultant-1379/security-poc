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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

public class AlgorithmPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    private static final String ALGORITHM_NAME = "name";
    private static final String ALGORITHM_TYPE = "type";
    private static final String ALGORITHM_KEYSIZE = "keySize";
    private static final String ALGORITHM_SUPPORTED = "supported";
    private static final String ALGORITHM_CATEGORIES = "categories";

    /**
     * Get algorithm data based on its name and key size.
     * 
     * @param name
     *            Name of the algorithm to be retrieved.
     * @param keySize
     *            The key size.
     * @return AlgorithmData
     * 
     * @throws CoreEntityServiceException
     *             Thrown to indicate any internal database errors.
     */

    public AlgorithmData getAlgorithmByNameAndKeySize(final String name, final Integer keySize) throws CoreEntityServiceException {

        AlgorithmData algorithmData = null;

        try {

            final HashMap<String, Object> parameters = new HashMap<>();
            parameters.put("name", name);
            parameters.put("keySize", keySize);

            final List<AlgorithmData> list = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (list != null && list.size() > 0) {
                algorithmData = (AlgorithmData) list.get(0);
            } else {
                logger.error("Couldn't find the algorithm {} with key size {} ", name, keySize);
                throw new CoreEntityServiceException("Couldn't find algorithm with name " + name + " and key size " + keySize);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithm from database", persistenceException);
            throw new CoreEntityServiceException("Exception while retrieving algorithm from database");
        }

        return algorithmData;
    }

    /**
     * Returns the list of algorithms based on name.
     * 
     * @param name
     *            Name of the algorithm.
     * 
     * @return List of Algorithm objects
     * 
     * @throws CoreEntityServiceException
     *             Thrown to indicate any internal database errors.
     */

    public List<AlgorithmData> getAlgorithmsByName(final String name) throws CoreEntityServiceException {

        List<AlgorithmData> algorithmDataList = null;
        try {

            final HashMap<String, Object> parameters = new HashMap<>();
            parameters.put("name", name);

            algorithmDataList = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                return algorithmDataList;
            } else {
                logger.error("Couldn't find the algorithms with name={} ", name);
                throw new CoreEntityServiceException("Couldn't find algorithms with name " + name);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithms from database", persistenceException);
            throw new CoreEntityServiceException(persistenceException);
        }
    }

    /**
     * Returns the list of algorithms based on name and Type.
     * 
     * @param algorithm
     * @param algorithmType
     * @return
     * 
     * @throws CoreEntityServiceException
     *             Thrown to indicate any internal database errors.
     */
    public AlgorithmData getAlgorithmByNameAndType(final Algorithm algorithm, final AlgorithmType algorithmType) throws CoreEntityServiceException {
        final Map<String, Object> input = new HashMap<>();

        final Set<Integer> categories = new HashSet<>();
        categories.add(AlgorithmCategory.OTHER.getId());

        input.put(ALGORITHM_NAME, algorithm.getName());
        input.put(ALGORITHM_CATEGORIES, categories);

        if (algorithmType.equals(AlgorithmType.SIGNATURE_ALGORITHM)) {
            input.put(ALGORITHM_TYPE, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        } else {
            final AlgorithmType type = algorithm.getType() == null ? AlgorithmType.ASYMMETRIC_KEY_ALGORITHM : algorithm.getType();
            input.put(ALGORITHM_TYPE, type.getId());
            input.put(ALGORITHM_KEYSIZE, algorithm.getKeySize());
        }

        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);
        List<AlgorithmData> algorithmFromDB = null;

        try {
            algorithmFromDB = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, input);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error when fetching algorithm with ", algorithm.getName(), " and  keysize ", algorithm.getKeySize());
            throw new CoreEntityServiceException(persistenceException);
        }

        return algorithmFromDB.get(0);
    }
}
