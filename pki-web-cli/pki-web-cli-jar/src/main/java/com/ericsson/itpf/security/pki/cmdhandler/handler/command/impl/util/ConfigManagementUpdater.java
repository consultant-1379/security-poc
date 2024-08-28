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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;

/**
 * Common implementation for algorithm update.
 *
 * @author xsumnan
 *
 */

public class ConfigManagementUpdater {
    @Inject
    private Logger logger;

    @Inject
    private AlgorithmUtils algorithmUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    /**
     * This is implementation of Configuration management Update handler, this will take care of updating algorithms
     * present in the system
     *
     * @see com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler #process
     *      (com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand)
     * @param algorithms
     * @param action
     *
     * @return PkiCommandResponse
     */

    public PkiCommandResponse update(final List<Algorithm> algorithms, final String action) {
        final boolean doEnable = action.equalsIgnoreCase(Constants.ENABLE) ? true : false;
        String commandResponseMsg = PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR;

        try {
            commandResponseMsg = updateAlgorithms(algorithms, doEnable);
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.CONSULT_ERROR_LOGS, algorithmNotFoundException.getMessage());
        } catch (final PKIConfigurationException pkiConfigurationException) {
            return prepareErrorMessage(ErrorType.PKICONFIG_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, pkiConfigurationException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, exception.getMessage());
        }

        return PkiCommandResponse.message(commandResponseMsg);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String errorMessage) {
        logger.error("Error occured while updating the algorithms: {}", errorMessage);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorString, errorMessage));
    }

    /**
     * Method for updating algorithms by changing their status either enable/disable
     *
     * @param algorithms
     * @param action
     * @return commandResponseMsg
     */
    public String updateAlgorithms(final List<Algorithm> algorithms, final boolean action) {
        final String commandResponseMsg = Constants.ALGORITHMS_UPDATED_SUCCESSFULLY;

        for (int index = 0; index < algorithms.size(); index++) {
            algorithms.get(index).setSupported(action);
        }

        eServiceRefProxy.getPkiConfigurationManagementService().updateAlgorithms(algorithms);

        return commandResponseMsg;
    }

    /**
     * Method for extracting algorithms from PkiPropertyCommand
     *
     * @param command
     * @return algorithms
     * @throws IllegalArgumentException
     */

    public List<Algorithm> extractAlgorithmList(final PkiPropertyCommand command) throws IllegalArgumentException {
        List<Algorithm> algorithms = new ArrayList<Algorithm>();

        final String algorithmName = command.getValueString(Constants.NAME);
        final String keySize = command.getValueString(Constants.KEY_SIZE);

        try {
            if (ValidationUtils.isNullOrEmpty(algorithmName)) {
                throw new IllegalArgumentException("Alogirthm Name cannot be empty or null");
            }

            if (ValidationUtils.isNullOrEmpty(keySize)) {
                final Algorithm algorithm = algorithmUtils.generateAlgorithm(algorithmName);
                algorithms.add(algorithm);
            } else {
                algorithms = generateAlgorithmsBasedOnInputCriteria(algorithmName, keySize);
            }
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            throw securityViolationException;
        } catch (final Exception exception) {
            logger.error("Exception occured during fetching algorithm with name {} and keysize {}, reason: {}", algorithmName, keySize, exception.getMessage());
            logger.debug("Error occured during fetching algorithms based on name and keysize: {}", exception.getStackTrace());
            throw new IllegalArgumentException(exception.getMessage());
        }
        if(algorithms != null){
            logger.debug("Algorithm Details: {}" , algorithms);
        }
        return algorithms;
}
    private List<Algorithm> generateAlgorithmsBasedOnInputCriteria(final String algorithmName, final String keySizes) {
        List<Algorithm> algorithmList = null;

        String keySizeFilter = keySizes.replaceAll("[\\[\\]]", "");
        keySizeFilter = keySizeFilter.replaceAll(" ", "");

        if (!keySizeFilter.matches(Constants.KEY_SIZE_REGEX)) {
            throw new IllegalArgumentException("Invalid argument: KeySize format error");
        }

        final List<Integer> keySizeList = algorithmUtils.splitBySeparator(keySizeFilter);

        final Matcher matcher = Pattern.compile(Constants.SUPPORTED_DELIMITERS_IN_KEY_SIZE).matcher(keySizeFilter);
        if (matcher.find()) {
            switch (matcher.group().charAt(0)) {
                case Constants.COMMA_DELIMITER:
                    algorithmList = algorithmUtils.generateAlgorithmsBasedOnMultipleKeySizes(algorithmName, keySizeList);
                    break;
                case Constants.HYPHEN_DELIMITER:
                    algorithmList = algorithmUtils.generateAlgorithmsBasedOnKeySizeRange(algorithmName, keySizeList);
                    break;
            }
        } else {
            algorithmList = algorithmUtils.generateAlgorithmsBasedOnMultipleKeySizes(algorithmName, keySizeList);
        }

        return algorithmList;
    }
}
