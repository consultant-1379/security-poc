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

import java.util.*;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;

/**
 *
 * Handler implementation for Crlmanagementunpublish. This provides service to unpublish the CRL from CDPS. "pkiadm" ("crlmgmt" | "crm" ) UNPUBLISH CA_ENTITY_NAME. UNPUBLISH :: ("--unpublish"|"-up")
 * CA_ENTITY_NAME::("caentityname"|"-caen")
 *
 * @author xsaufar
 *
 */

@CommandType(PkiCommandType.CRLMANAGEMENTUNPUBLISH)
@Local(CommandHandlerInterface.class)
public class CRLManagementUnPublishCRLHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    private static final String UNSUCCESFUL_MSG = "CRL(s) unpublishing failed for %s. Please check the details below.";
    private static final String SUCCESFUL_MSG = "CRL(s) unpublished successfully from CDPS by %s";
    private static final String BOTH = "CRL(s) unpublished successfully from CDPS by %s. CRL(s) unpublishing failed for %s. Please check the details below.";
    private PkiCommandResponse commandResponse = null;

    /**
     * Method implementation for CRLManagementUnPublishCRLHandler.Processes the command to generate the CRL from service.
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.debug("CRLMANAGEMENTUNPUBLISH command handler");

        try {
            final String cAName = command.getValueString(Constants.CA_ENTITY_NAME);

            if (ValidationUtils.isNullOrEmpty(cAName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            final List<String> cANameList = cliUtil.splitBySeprator(cliUtil.removeFirstAndLastChar(cAName), Constants.SUPPORTED_DELIMITERS_IN_CA_NAMES);
            final Map<String, CRLPublishUnpublishStatus> caCrlUnpublishStatusMap = unpublishfromCDPS(cANameList);

            commandResponse = prepareResponseMessage(caCrlUnpublishStatusMap);

        } catch (final CANotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, entityNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final CRLServiceException crlServiceException) {
            return prepareErrorMessage(ErrorType.REVOCATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, crlServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CRLMANAGEMENTUNPUBLISH", "CRLManagementUnPublishCRLHandler",
                "CRL of CA entity: " + command.getValueString(Constants.CA_ENTITY_NAME) + " unpublished successfully from CDPS",
                "Unpublish CRL from CDPS", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return commandResponse;
    }

    private Map<String, CRLPublishUnpublishStatus> unpublishfromCDPS(final List<String> cANameList) throws CRLServiceException, CANotFoundException {

        return eServiceRefProxy.getCrlManagementService().unpublishCRLFromCDPS(cANameList);
    }

    private PkiCommandResponse prepareResponseMessage(final Map<String, CRLPublishUnpublishStatus> caCrlUnpublishStatusMap) throws CRLServiceException {
        final StringBuilder successfulUnpublishedItems = new StringBuilder();
        final StringBuilder unsuccessfulUnpublishedItems = new StringBuilder();
        final int numberOfColumns = Constants.CRL_HEADER.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);
        commandResponse.add(Constants.ENTITY_NAME, Constants.CRL_HEADER);

        if (caCrlUnpublishStatusMap.size() == 0) {
            throw new CRLServiceException("Failed to get Status");
        }

        final Iterator<Map.Entry<String, CRLPublishUnpublishStatus>> caCrlUnpublishStatusEntries = caCrlUnpublishStatusMap.entrySet().iterator();
        while (caCrlUnpublishStatusEntries.hasNext()) {
            final Map.Entry<String, CRLPublishUnpublishStatus> caCrlUnpublishStatusEntry = caCrlUnpublishStatusEntries.next();

            final CRLPublishUnpublishStatus crlPublishUnpublishStatus = caCrlUnpublishStatusEntry.getValue();
            switch (crlPublishUnpublishStatus) {
            case SENT_FOR_UNPUBLISH:
                successfulUnpublishedItems.append(caCrlUnpublishStatusEntry.getKey()).append(", ");
                continue;
            case CA_ENTITY_NOT_FOUND:
                commandResponse.add(caCrlUnpublishStatusEntry.getKey(), new String[] { cliUtil.getErrorCode(ErrorType.CA_NOT_FOUND_EXCEPTION).toString(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION });
                unsuccessfulUnpublishedItems.append(caCrlUnpublishStatusEntry.getKey()).append(", ");
                continue;
            case CRL_INFO_NOT_FOUND:
                commandResponse.add(caCrlUnpublishStatusEntry.getKey(), new String[] { cliUtil.getErrorCode(ErrorType.CRL_NOT_FOUND_EXCEPTION).toString(), PkiErrorCodes.CRL_NOT_FOUND_FOR_DOWNLOAD_CRL });
                unsuccessfulUnpublishedItems.append(caCrlUnpublishStatusEntry.getKey()).append(", ");
                continue;
            case VALID_CRL_NOT_FOUND:
                commandResponse.add(caCrlUnpublishStatusEntry.getKey(), new String[] { cliUtil.getErrorCode(ErrorType.CRL_NOT_FOUND_EXCEPTION).toString(), "Valid CRL not found for CA entity" });
                unsuccessfulUnpublishedItems.append(caCrlUnpublishStatusEntry.getKey()).append(", ");
                continue;

            default:
                logger.error("Invalid crl publish status {} for caName {}", crlPublishUnpublishStatus, caCrlUnpublishStatusEntry.getKey());
            }
        }

        return prepareResponseMessage(cliUtil.removeUnwantedCommaFromString(successfulUnpublishedItems), cliUtil.removeUnwantedCommaFromString(unsuccessfulUnpublishedItems), commandResponse);
    }

    private PkiCommandResponse prepareResponseMessage(final String successfulList, final String unSuccessfulList, final PkiNameMultipleValueCommandResponse commandResponse) {
        String msg = "";

        if (!successfulList.isEmpty() && !unSuccessfulList.isEmpty()) {
            msg = String.format(BOTH, successfulList, unSuccessfulList);
            commandResponse.setAdditionalInformation(msg);
            return commandResponse;
        }

        if (!successfulList.isEmpty()) {
            msg = String.format(SUCCESFUL_MSG, successfulList);
            return PkiCommandResponse.message(msg);
        }

        if (!unSuccessfulList.isEmpty()) {
            msg = String.format(UNSUCCESFUL_MSG, unSuccessfulList);
            commandResponse.setAdditionalInformation(msg);
            return commandResponse;
        }

        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while unpublishing the CRL: {} " , PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while unpublishing the CRL: {} " , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }


}
