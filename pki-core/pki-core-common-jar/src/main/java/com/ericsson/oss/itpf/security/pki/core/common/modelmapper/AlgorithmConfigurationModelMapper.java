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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;

/**
 * Converts Algorithm api model to AlgorithmData jpa model and vice versa.
 * 
 * @author xprabil
 * 
 */
public class AlgorithmConfigurationModelMapper {

    private AlgorithmConfigurationModelMapper() {

    }

    /**
     * Convert list of Algorithm api model objects to AlgorithmData entity objects.
     * 
     * @param algorithmList
     *            list of Algorithm api models.
     * 
     * @return the list of AlgorithmData(JPA Entity).
     */
    public static AlgorithmData[] toAlgorithmData(final List<Algorithm> algorithmList) {
        final List<AlgorithmData> algorithmDataList = new ArrayList<>();
        AlgorithmData algorithmData;

        for (final Algorithm algorithm : algorithmList) {
            algorithmData = toAlgorithmData(algorithm);
            algorithmDataList.add(algorithmData);
        }

        return algorithmDataList.toArray(new AlgorithmData[0]);
    }

    /**
     * Convert Algorithm api model object to AlgorithmData entity object.
     * 
     * @param algorithm
     *            Algorithm api model.
     * 
     * @return AlgorithmData(JPA Entity).
     */
    public static AlgorithmData toAlgorithmData(final Algorithm algorithm) {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setOid(algorithm.getOid());
        algorithmData.setName(algorithm.getName());
        algorithmData.setType(algorithm.getType());
        algorithmData.setSupported(algorithm.isSupported());
        algorithmData.setKeySize(algorithm.getKeySize());

        return algorithmData;
    }

    /**
     * Convert list of AlgorithmData entity objects to Algorithm api model objects.
     * 
     * @param algorithmDataList
     *            list of AlgorithmData entity objects
     * 
     * @return the list of Algorithm api model objects.
     */
    public static List<Algorithm> fromAlgorithmData(final List<AlgorithmData> algorithmDataList) {

        final List<Algorithm> algorithmList = new ArrayList<>();
        for (final AlgorithmData algorithmData : algorithmDataList) {
            final Algorithm algorithm = fromAlgorithmData(algorithmData);
            algorithmList.add(algorithm);
        }

        return algorithmList;
    }

    /**
     * Convert AlgorithmData entity object to Algorithm api model object.
     * 
     * @param algorithmData
     *            AlgorithmData entity object.
     * 
     * @return Algorithm api model object.
     */
    public static Algorithm fromAlgorithmData(final AlgorithmData algorithmData) {
        final Algorithm algorithm = new Algorithm();

        algorithm.setId(algorithmData.getId());
        algorithm.setOid(algorithmData.getOid());
        algorithm.setName(algorithmData.getName());
        algorithm.setType(algorithmData.getType());
        algorithm.setSupported(algorithmData.isSupported());
        algorithm.setKeySize(algorithmData.getKeySize());

        return algorithm;
    }

}
