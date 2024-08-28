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

package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;

/**
 * <p>
 * Class for utilities for algorithms
 * <p>
 * 
 * @author xsumnan
 * 
 */
public class AlgorithmUtils {
    @Inject
    private Logger logger;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    /**
     * <p>
     * Method for splitting a string with delimiter like , -
     * </p>
     * 
     * @param input
     * @param delimiter
     * @return List<Integer>
     */
    public List<Integer> splitBySeparator(final String input) {
	final List<Integer> result = new ArrayList<Integer>();

	final String[] keySizes = input.split(Constants.SUPPORTED_DELIMITERS_IN_KEY_SIZE);

	for (final String keySize : keySizes) {
	    try {
		final int value = Integer.parseInt(keySize.trim());
		result.add(value);
	    } catch (final NumberFormatException numberFormatException) {
		logger.error("Error occured during split By Separate: " + numberFormatException.getMessage());
		throw numberFormatException;
	    }
	}

	Collections.sort(result);

	return result;
    }

    /**
     * Method for creating algorithm instances from algorithms list
     * 
     * @param algorithmName
     * @param keySizes
     * @return List of Algorithms
     */
    public List<Algorithm> generateAlgorithmsBasedOnMultipleKeySizes(final String algorithmName,
	    final List<Integer> keySizes) {
	final List<Algorithm> algorithmList = new ArrayList<Algorithm>();

	for (final Integer keySize : keySizes) {
	    final Algorithm algorithm = generateAlgorithm(algorithmName, keySize);
	    algorithmList.add(algorithm);
	}

	return algorithmList;
    }

    /**
     * Method for creating algorithm instance with algorithm name
     * 
     * @param algorithmName
     * @return Algorithm
     */
    public Algorithm generateAlgorithm(final String algorithmName) {
	return generateAlgorithm(algorithmName, null);
    }

    /**
     * Method for creating algorithm instance with provided name and keysize
     */
    public Algorithm generateAlgorithm(final String algorithmName, final Integer keySize) {
	final Algorithm algorithm = new Algorithm();

	algorithm.setName(algorithmName);
	algorithm.setKeySize(keySize);

	return algorithm;
    }

    /**
     * Method for fetching algorithms based on keysize range
     * 
     * @param algorithmName
     * @param keySizes
     * @return List of Algorithms
     */
    public List<Algorithm> generateAlgorithmsBasedOnKeySizeRange(final String algorithmName,
	    final List<Integer> keySizes) {
	final int minKeySize = keySizes.get(0);
	final int maxKeySize = keySizes.get(keySizes.size() - 1);

	final List<Algorithm> algorithmsFromDB = getAlgorithmsByName(algorithmName);

	final List<Algorithm> algorithms = new ArrayList<Algorithm>();
	for (final Algorithm algorithm : algorithmsFromDB) {
	    if (algorithm.getKeySize() >= minKeySize && algorithm.getKeySize() <= maxKeySize) {
		algorithms.add(algorithm);
	    }
	}

	return algorithms;
    }

    /**
     * Method for fetching algorithms based on name from configuration service
     * 
     * @param algorithmName
     * @return List of Algorithms
     */
    public List<Algorithm> getAlgorithmsByName(final String algorithmName) {
	List<Algorithm> algorithms = null;

	try {

	    algorithms = eServiceRefProxy.getPkiConfigurationManagementService().getAlgorithmsByName(algorithmName);

	} catch (AlgorithmNotFoundException exception) {
	    logger.error("Unable to fetch the algorithm list based on algorithm Name: " + algorithmName
		    + " - Error Msg: " + exception.getMessage());
	    throw exception;
	} catch (Exception exception) {
	    logger.error("Unable to fetch the algorithm list based on algorithm Name: " + algorithmName
		    + " - Error Msg: " + exception.getMessage());
	    throw exception;
	}

	return algorithms;
    }
}
