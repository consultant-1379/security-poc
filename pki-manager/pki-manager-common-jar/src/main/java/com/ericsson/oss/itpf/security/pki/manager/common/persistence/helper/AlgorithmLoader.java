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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.helper;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

public class AlgorithmLoader {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

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
        logger.info("getSupportedAlgorithmsByType method in AlgorithmLoader");
        List<Algorithm> algorithmList = null;
        final Set<Integer> algorithmTypeList = new HashSet<Integer>();
        try {
            if (algorithmTypes == null) {
                logger.error(ErrorMessages.ALGORITHMTYPES_SHOULDNOTBENULL);
                throw new PKIConfigurationServiceException(ErrorMessages.ALGORITHMTYPES_SHOULDNOTBENULL);
            }
            for (final AlgorithmType algorithmType : algorithmTypes) {
                algorithmTypeList.add(algorithmType.getId());
            }
            final Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("supported", true);
            parameters.put("type", algorithmTypeList);

            final List<AlgorithmData> algorithmDataList = persistenceManager.findEntitiesWhere(AlgorithmData.class, parameters);

            if (algorithmDataList != null && algorithmDataList.size() > 0) {
                algorithmList = AlgorithmConfigurationModelMapper.fromAlgorithmData(algorithmDataList);
            } else {
                logger.error("Couldn't find the algorithms with the given type" + ErrorMessages.ALGORITHM_NOT_FOUND);
                throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND);
            }

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException);
            throw new PKIConfigurationServiceException(ErrorMessages.INTERNAL_ERROR + persistenceException);
        }
        logger.info("End of getSupportedAlgorithmsByType method in AlgorithmLoader");
        return algorithmList;
    }

}
