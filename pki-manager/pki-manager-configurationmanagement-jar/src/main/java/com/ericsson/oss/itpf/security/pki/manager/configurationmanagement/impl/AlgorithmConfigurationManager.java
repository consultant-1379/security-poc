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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.InvalidConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SupportedAlgorithmsCacheOperations;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * Class for Managing all the Algorithm Configurations. Gets the call from PKI Configuration manager EJB.
 * 
 */
public class AlgorithmConfigurationManager {

    @Inject
    private PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @EJB
    private SupportedAlgorithmsCacheOperations supportedAlgorithmCacheOperations;

    @Inject
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Get List of AlgorithmData objects based on algorithm types data.
     * 
     * @param algorithmTypes
     *            enum containing types of algorithms.
     * @return List of Algorithm objects.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown in case of algorithm not found for the given Type.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */

    public List<Algorithm> getAlgorithmsByType(final AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        List<Algorithm> algorithmList = null;
        final Set<Integer> algorithmTypeSet = new HashSet<Integer>();
        try {
            if (algorithmTypes == null) {
                throw new IllegalArgumentException(ErrorMessages.ALGORITHMTYPES_SHOULDNOTBENULL);
            }
            for (AlgorithmType algorithmType : algorithmTypes) {
                algorithmTypeSet.add(algorithmType.getId());
            }
            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("type", algorithmTypeSet);

            final List<AlgorithmData> algorithmDataList = persistenceManager.findEntitiesWhere(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                algorithmList = AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmDataList);
            } else {
                logger.error("Couldn't find the algorithms with the given type");
                throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND);
            }

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException);
            throw new PKIConfigurationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
        return algorithmList;
    }

    /**
     * Get list of supported AlgorithmData objects based on algorithm types data.
     * 
     * @param algorithmTypes
     *            enum containing types of algorithms.
     * @return List of Algorithm objects.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown in case of algorithm not found for the given Type.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */

    public List<Algorithm> getSupportedAlgorithmsByType(final AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        List<Algorithm> algorithmList = null;
        final Set<Integer> algorithmTypeList = new HashSet<Integer>();
        try {
            if (algorithmTypes == null) {
                throw new IllegalArgumentException(ErrorMessages.ALGORITHMTYPES_SHOULDNOTBENULL);
            }
            for (AlgorithmType algorithmType : algorithmTypes) {
                algorithmTypeList.add(algorithmType.getId());
            }
            final Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("supported", true);
            parameters.put("type", algorithmTypeList);

            final List<AlgorithmData> algorithmDataList = persistenceManager.findEntitiesWhere(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                algorithmList = AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmDataList);
            } else {
                logger.error("Couldn't find the algorithms with the given type");
                throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND);
            }

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException);
            throw new PKIConfigurationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
        return algorithmList;
    }

    /**
     * Updates algorithms to supported or unsupported in the system. If trying to update Key Generation algorithm specify both algorithm name and key size. For other type of algorithms only name is
     * required.
     * 
     * @param algorithms
     *            Map of algorithm names and supported flag to be set.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown in case of algorithm not found for the given name.
     * @throws InvalidConfigurationException
     *             Thrown when keySize is not provided for updating keyGenerationAlgorithm.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    public void updateAlgorithms(final List<Algorithm> updateAlgorithms) throws AlgorithmNotFoundException, InvalidConfigurationException, PKIConfigurationServiceException {
        try {
            for (final Algorithm algorithm : updateAlgorithms) {
                final AlgorithmData updateAlgorithmData;
                if (algorithm.getKeySize() != null && algorithm.getKeySize() > 0) {
                    updateAlgorithmData = algorithmPersistenceHandler.getAlgorithmByNameAndKeySize(algorithm.getName(), algorithm.getKeySize());
                } else {
                    updateAlgorithmData = algorithmPersistenceHandler.getAlgorithmsByName(algorithm.getName()).get(0);
                    if (AlgorithmType.ASYMMETRIC_KEY_ALGORITHM == AlgorithmType.getType(updateAlgorithmData.getType())
                            || AlgorithmType.SYMMETRIC_KEY_ALGORITHM == AlgorithmType.getType(updateAlgorithmData.getType())) {
                        logger.error("Couldn't update the algorithm {}, as it is KeyGeneration algorithm. Key Size must be specified", algorithm.getName());
                        throw new InvalidConfigurationException("Could not update the algorithm = " + algorithm.getName()
                                + " because it is of type KeyGeneration. Please specify key size to update the same");
                    }
                }
                updateAlgorithmData.setSupported(algorithm.isSupported());
                persistenceManager.updateEntity(updateAlgorithmData);
                supportedAlgorithmCacheOperations.update(updateAlgorithmData);
            }
            systemRecorder.recordSecurityEvent("Configuration Management Service", "AlgorithmConfigurationManager", "Algorithms " + getAlgorithmNames(updateAlgorithms)
                    + "are updated in the database ", "CONFIGURATIONMANAGEMENT.UPDATE_ALGORITHMS", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (PersistenceException persistenceException) {
            logger.error("Exception while updating algorithms in database", persistenceException);
            throw new PKIConfigurationServiceException(persistenceException);
        }

    }

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

    public <T> Algorithm getAlgorithmByNameAndKeySize(final String name, final Integer keySize) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        Algorithm algorithm = null;

        try {

            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("name", name);
            parameters.put("keySize", keySize);

            final List<AlgorithmData> list = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (list != null && list.size() > 0) {
                final AlgorithmData algorithmData = (AlgorithmData) list.get(0);
                algorithm = AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmData);
            } else {
                logger.error("Couldn't find the algorithm {} with key size {} ", name, keySize);
                throw new AlgorithmNotFoundException("Couldn't find algorithm with name " + name + " and key size " + keySize);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithm from database", persistenceException);
            throw new PKIConfigurationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }

        return algorithm;
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

    public List<Algorithm> getAlgorithmsByName(final String name) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        List<Algorithm> algorithmList = null;
        try {

            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("name", name);

            final List<AlgorithmData> algorithmDataList = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                algorithmList = AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmDataList);
            } else {
                logger.error("Couldn't find the algorithms with name={} ", name);
                throw new AlgorithmNotFoundException("Couldn't find algorithms with name " + name);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Exception while retrieving algorithms from database", persistenceException);
            throw new PKIConfigurationServiceException(persistenceException);
        }
        return algorithmList;

    }

    private List<String> getAlgorithmNames(final List<Algorithm> algorithms) {

        final List<String> algorithmNamesList = new ArrayList<String>();
        for (final Algorithm algorithm : algorithms) {
            algorithmNamesList.add(algorithm.getName());
        }
        return algorithmNamesList;
    }
}
