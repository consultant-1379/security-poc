/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

/**
 * Handler implementation for ConfigManagementCategoryCreateHandler. This provides service to create a new entity category.
 *
 * pkiadm ("configmgmt"|"cfg") category CREATE CATEGORY_NAME CREATE ::= ("--create"|"-c") CATEGORY_NAME ::= ("--name"|"-n") <categoryName>
 *
 *
 * @author xnanbot
 */
@CommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYCREATE)
@Local(CommandHandlerInterface.class)
public class ConfigManagementCategoryCreateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation for ConfigManagementCategoryCreateHandler. Processes the command to create entity category from service.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CONFIGMANAGEMENTCATEGORYCREATE command handler");

        final String categoryName = command.getValueString(Constants.NAME);

        if (ValidationUtils.isNullOrEmpty(categoryName)) {
            return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY);
        }

        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName(categoryName);
        entityCategory.setModifiable(true);
        try {
            eServiceRefProxy.getPkiConfigurationManagementService().createCategory(entityCategory);

        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(invalidEntityCategoryException.getMessage(), invalidEntityCategoryException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final EntityCategoryAlreadyExistsException entityCategoryAlreadyExistsException) {
            logger.debug(entityCategoryAlreadyExistsException.getMessage(), entityCategoryAlreadyExistsException);
            return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_ALREADY_EXIST_EXCEPTION.toInt(), entityCategoryAlreadyExistsException.getMessage());
        } catch (final PKIConfigurationServiceException pkiConfigurationServiceException) {
            return prepareErrorMessage(ErrorType.PKI_CONFIGURATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    pkiConfigurationServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), Constants.ERROR_WHILE_CREATING + Constants.SPACE_STRING + entityCategory + Constants.SPACE_STRING + exception.getMessage(),
                    exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CONFIGMANAGEMENTCATEGORYCREATE", "ConfigManagementCategoryCreateHandler",
                "Entity category created successfully with name: " + categoryName, "Create entity category", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return PkiCommandResponse.message(Constants.CATEGORY_CREATED_SUCCESSFULLY);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error:{} occured when creating entity category: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error:{} occured when creating entity category: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage,Constants.EMPTY_STRING);

    }
}
