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

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCACRLsExistException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * <p>
 * Handler implementation for EntityManagementDeleteExtCA. This provides service to delete ext CA
 * </p>
 *
 * "pkiadm" "extcaremove" EXT_CA_NAME EXT_CA_NAME ::= ( "-n" | "--name" ) " " <ca-name-value>
 *
 */

@CommandType(PkiCommandType.EXTERNALCAREMOVE)
@Local(CommandHandlerInterface.class)
public class EntityManagementDeleteExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    private static final String DELETE_ENTITY_ERROR = "Error while deleting entity ";

    @Inject
    Logger logger;

    @Inject
    CliUtil cliutil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation for EntityManagementDeleteExtCAHandler. Processes the command for deletion of external CA
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("EXTERNALCAREMOVE command handler");

        String commandResponseMsg = PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR;
        try {
            final String entityName = command.getValueString(Constants.NAME);

            commandResponseMsg = deleteEntity(entityName);
            systemRecorder.recordEvent("PKISERVICE.EXTERNALCASERVICE", EventLevel.COARSE, "PKI.EXTERNALCAREMOVE", "External CA removed " + command.getValueString(Constants.NAME),
                    "Successfully removed External CA.");
        } catch (final MissingMandatoryFieldException ex) {
            logger.error(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex.getMessage());
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + ex.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCANotFoundException entityNotFoundException) {
            logger.error(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + entityNotFoundException.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCAInUseException entityInUseException) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, entityInUseException.getMessage());
            logger.debug(entityInUseException.getMessage(), entityInUseException);
            return prepareErrorMessage(ErrorType.EXTCA_USED_IN_TRUSTPROFILE.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + entityInUseException.getMessage(), Constants.EMPTY_STRING);
        } catch (final ExternalCACRLsExistException e) {
            logger.error(DELETE_ENTITY_ERROR, e.getMessage());
            logger.debug(e.getMessage(), e);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), DELETE_ENTITY_ERROR, e.getMessage());
        } catch (final ExternalCredentialMgmtServiceException internalServiceException) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, internalServiceException.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, internalServiceException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), DELETE_ENTITY_ERROR, PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.RETRY);
        } catch (final CommonRuntimeException commonRuntimeException) {
            logger.error(PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException.getMessage());
            logger.debug(PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException);
            return prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliutil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(exception.getMessage(), exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        return PkiCommandResponse.message(commandResponseMsg);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while deleting the external CA: {} ", errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);

    }

    private String deleteEntity(final String entityName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCredentialMgmtServiceException,
            ExternalCACRLsExistException {
        String returnMsg = "";

        if (entityName == null) {
            returnMsg += "Unable to delete the ca. caName is mandatory Parameters";
        } else {
            eServiceRefProxy.getExtCaCrlManagementService().remove(entityName);
            eServiceRefProxy.getExtCaCertificateManagementService().remove(entityName);
            returnMsg += "External CA " + " with name: " + entityName + Constants.SUCCESSFULLY_DELETED;
        }

        return returnMsg;
    }
}
