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

package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliPredicate;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;

/**
 * Handler implementation for ConfigManagementList. This provides service to list algorithms
 *
 * pkiadm (configmgmt|cfg) algo --list|-l --type|-t (all|signature|keygen|digest) --status|-s <all|enabled|disabled>
 *
 * @author xsumnan
 *
 */
@CommandType(PkiCommandType.CONFIGMGMTLIST)
@Local(CommandHandlerInterface.class)
public class ConfigManagementListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    final String[] algorithmHeader = { "Algorithm Type", "Key Size", "Status" };

    /**
     * Method implementation for ConfigManagementList, processing the command for listing of algorithm(s)
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CONFIGMGMTLIST command handler");

        final String algorithmType = command.getValueString(Constants.ALGORITHM_TYPE).toLowerCase();
        final String algorithmStatus = command.getValueString(Constants.ALGORITHM_STATUS).toLowerCase();

        PkiCommandResponse commandResponse = null;

        try {
            final AlgorithmType[] algorithmTypes = getAlgorithmFilterCriteria(algorithmType);

            final List<Algorithm> algorithms = getAlgorithmsByStatus(algorithmTypes, algorithmStatus);
            commandResponse = buildCommandResponse(algorithms);

        }catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            logger.error(PkiErrorCodes.ALGORITHM_NOT_FOUND_WITH_STATUS + Constants.SPACE_STRING + algorithmNotFoundException.getMessage());
            commandResponse = prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_WITH_STATUS);
        } catch (final PKIConfigurationServiceException configurationServiceException) {
            logger.error(PkiErrorCodes.CONSULT_ERROR_LOGS + Constants.SPACE_STRING + configurationServiceException.getMessage());
            logger.debug(PkiErrorCodes.CONSULT_ERROR_LOGS + Constants.SPACE_STRING + configurationServiceException.getMessage(), configurationServiceException);
            commandResponse = prepareErrorMessage(ErrorType.PKICONFIG_ERROR.toInt(), PkiErrorCodes.CONSULT_ERROR_LOGS);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + " Exception occured while listing the algorithm by Status "
                    + illegalArgumentException.getMessage(), illegalArgumentException);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.SPACE_STRING + exception.getMessage());
            commandResponse = prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CONFIGMGMTLIST", "ConfigManagementListHandler",
                "Algorithm(s) listed successfully based on type: " + algorithmType + " and status: " + algorithmStatus, "List algorithm(s)",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while listing the algorithms {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage,cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the algorithms: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private AlgorithmType[] getAlgorithmFilterCriteria(final String algorithmType) throws IllegalArgumentException {
        final List<AlgorithmType> algorithmTypes = new ArrayList<>();

        switch (algorithmType) {
            case "signature":
                algorithmTypes.add(AlgorithmType.SIGNATURE_ALGORITHM);
                break;
            case "digest":
                algorithmTypes.add(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
                break;
            case "asymmetric":
                algorithmTypes.add(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
                break;
            case "symmetric":
                algorithmTypes.add(AlgorithmType.SYMMETRIC_KEY_ALGORITHM);
                break;
            case "all":
                algorithmTypes.add(AlgorithmType.SIGNATURE_ALGORITHM);
                algorithmTypes.add(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
                algorithmTypes.add(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
                algorithmTypes.add(AlgorithmType.SYMMETRIC_KEY_ALGORITHM);
                break;
            default:
                throw new IllegalArgumentException("Algorithm Type: " + algorithmType + " is not Support");
        }

        return algorithmTypes.toArray(new AlgorithmType[] {});
    }

    private List<Algorithm> getAlgorithmsByStatus(final AlgorithmType[] algorithmTypes, final String algorithmStatus) throws  AlgorithmNotFoundException, PKIConfigurationServiceException {
        final List<Algorithm> algorithms = eServiceRefProxy.getPkiConfigurationManagementService().getAlgorithmsByType(algorithmTypes);

        List<Algorithm> filteredAlgorithms = null;
        filteredAlgorithms = getFilteredAlgorithmList(algorithms, algorithmStatus);

        return filteredAlgorithms;
    }

    private List<Algorithm> getFilteredAlgorithmList(final List<Algorithm> algorithms, final String algorithmStatus) {
        if (CliUtil.isNullOrEmpty(algorithms)) {
            return null;
        }

        final CliPredicate<Algorithm> algorithmPredicate = new CliPredicate<Algorithm>() {
            @Override
            public boolean apply(final Algorithm algorithm) {
                if (algorithmStatus.equalsIgnoreCase(Constants.ALL)) {
                    return true;
                }

                final boolean isAlgorithmEnabled = algorithmStatus.equalsIgnoreCase(Constants.ENABLED);
                final boolean isAlorithmSupported = algorithm.isSupported();

                return isAlorithmSupported == isAlgorithmEnabled;
            }
        };

        final List<Algorithm> filteredAlgorithmList = CliUtil.filter(algorithms, algorithmPredicate);

        return filteredAlgorithmList;
    }

    private PkiCommandResponse buildCommandResponse(final List<Algorithm> algorithms) {
        if (CliUtil.isNullOrEmpty(algorithms)) {
            throw new AlgorithmNotFoundException(Constants.NO_ALGORITHM_FOUND_MATCHING_CRITERIA);
        }

        return buildPkiNameMultipleValueCommandResponse(algorithms);
    }

    private PkiNameMultipleValueCommandResponse buildPkiNameMultipleValueCommandResponse(final List<Algorithm> algorithms) {
        final int numberOfColumns = algorithmHeader.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation("Following is the list of algorithm(s) available in the system");
        commandResponse.add(Constants.ALGORITHM_NAME, algorithmHeader);

        for (final Algorithm algorithm : algorithms) {
            commandResponse.add(algorithm.getName(), getAlgorithmDetails(algorithm));
        }

        return commandResponse;
    }

    private String[] getAlgorithmDetails(final Algorithm algorithm) {
        final String status = algorithm.isSupported() ? Constants.ENABLED : Constants.DISABLED;
        final String[] algorithmDetails = { algorithm.getType() + Constants.EMPTY_STRING, algorithm.getKeySize() == null ? "-" : algorithm.getKeySize() + Constants.EMPTY_STRING,
                status + Constants.EMPTY_STRING };

        return algorithmDetails;
    }
}