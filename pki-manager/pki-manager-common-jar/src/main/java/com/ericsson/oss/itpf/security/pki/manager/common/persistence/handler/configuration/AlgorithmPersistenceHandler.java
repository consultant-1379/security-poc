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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

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
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown in case of algorithm not found for the given name.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */

    public AlgorithmData getAlgorithmByNameAndKeySize(final String name, final Integer keySize) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        AlgorithmData algorithmData = null;

        try {

            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("name", name);
            parameters.put("keySize", keySize);

            final List<AlgorithmData> list = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (list != null && list.size() > 0) {
                algorithmData = (AlgorithmData) list.get(0);
            } else {
                logger.error("Couldn't find the algorithm {} with key size {} ", name, keySize);
                throw new AlgorithmNotFoundException("Couldn't find algorithm with name " + name + " and key size " + keySize);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithm from database", persistenceException);
            throw new PKIConfigurationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
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
     * @throws AlgorithmNotFoundException
     *             Thrown in case of algorithm not found for the given name.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */

    public List<AlgorithmData> getAlgorithmsByName(final String name) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        List<AlgorithmData> algorithmDataList = null;
        try {

            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("name", name);

            algorithmDataList = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                return algorithmDataList;
            } else {
                logger.error("Couldn't find the algorithms with name={} ", name);
                throw new AlgorithmNotFoundException("Couldn't find algorithms with name " + name);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithms from database", persistenceException);
            throw new PKIConfigurationServiceException(persistenceException);
        }
    }

    /**
     * @param algorithm
     * @param algorithmType
     * @return
     * @throws AlgorithmException
     */
    public AlgorithmData getAlgorithmByNameAndType(final Algorithm algorithm, final AlgorithmType algorithmType) throws AlgorithmException {
        final Map<String, Object> input = new HashMap<String, Object>();

        final Set<Integer> categories = new HashSet<Integer>();
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
        AlgorithmData algorithmFromDB = null;

        try {
            algorithmFromDB = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error when fetching algorithm with ", algorithm.getName(), " and  keysize ", algorithm.getKeySize());
            throw new AlgorithmException(persistenceException);
        }

        return algorithmFromDB;
    }

}
