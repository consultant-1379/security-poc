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
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * <p>
 * Handler implementation for TrustManagementUnPublishHandler This provides service to perform unpublish operation for CA/END Entity.
 * </p>
 *
 * "pkiadm" ( "trustmgmt" | "tsm" ) UNPUBLISH ENTITY_TYPE ENTITY_NAME
 *
 * UNPUBLISH ::= ("--unpublish"|"-up")
 *
 * ENTITY_TYPE ::= ("--entitytype"|"-type") ENT_TYPE
 *
 * ENT_TYPE ::= "ca" | "ee"
 *
 * ENTITY_NAME ::= ("--entityname"|"-en") " " <entity_name>
 *
 * @author xlaktum
 */

@CommandType(PkiCommandType.TRUSTMANAGEMENTUNPUBLISH)
@Local(CommandHandlerInterface.class)
public class TrustManagementUnPublishHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    private static final String SUCCESS_MESSAGE_EE = "End Entity certificates are unpublished successfully from Trust Distribution Point Service.";
    private static final String SUCCESS_MESSAGE_CA = "CA Entity certificates are unpublished successfully.";

    /**
     * Method implementation of TrustManagementUnPublishHandler. Processes the command to perform unpublish operation for CA/END Entity.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.debug("TRUSTMANAGEMENUNPBLISH command handler");

        PkiCommandResponse pkiCommandResponse = null;
        try {
            final String entityType = command.getValueString(Constants.ENTITY_TYPE);
            final String entityName = command.getValueString(Constants.ENTITYNAME).replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, Constants.EMPTY_STRING);

            switch (entityType) {

                case "ca":
                    eServiceRefProxy.getCaCertificateManagementService().unPublishCertificate(entityName);
                    pkiCommandResponse = prepareSuccessMessage(SUCCESS_MESSAGE_CA);
                systemRecorder.recordSecurityEvent("PKIWebCLI.TRUSTMANAGEMENTUNPUBLISH", "TrustManagementUnPublishHandler", "CA entity: "
                        + entityName + " unpublished successfully", "Unpublish CA entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
                    break;
                case "ee":
                    eServiceRefProxy.getEntityCertificateManagementService().unPublishCertificate(entityName);
                    pkiCommandResponse = prepareSuccessMessage(SUCCESS_MESSAGE_EE);
                systemRecorder.recordSecurityEvent("PKIWebCLI.TRUSTMANAGEMENTUNPUBLISH", "TrustManagementUnPublishHandler", "End Entity: "
                        + entityName + " unpublished successfully", "Unpublish end entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
                    break;
            }
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final CANotFoundException caNotFoundException) {
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final EntityNotFoundException entityNotFoundException) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while unpublishing the Trust Certificates : {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while unpublishing the Trust Certificates: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private PkiCommandResponse prepareSuccessMessage(final String message) {
        return PkiCommandResponse.message(message);
    }
}
