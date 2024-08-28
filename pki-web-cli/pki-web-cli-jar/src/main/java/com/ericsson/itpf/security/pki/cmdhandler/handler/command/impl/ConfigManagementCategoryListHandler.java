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
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

/**
 * Handler implementation for ConfigManagementCategoryListHandler. This provides service to list entity category.
 *
 * pkiadm ("configmgmt"|"cfg") category LIST [CATEGORY_NAME] LIST ::= ("--list"|"-l") CATEGORY_NAME ::= ("--name"|"-n") <categoryName>
 *
 * @author xnanbot
 */

@CommandType(PkiCommandType.CONFIGMANAGEMENTCATEGORYLIST)
@Local(CommandHandlerInterface.class)
public class ConfigManagementCategoryListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    String[] categoryHeader = { "Modifiable" };

    /**
     * Method implementation for ConfigManagementCategoryListHandler. Processes the command to update list category from service.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CONFIGMANAGEMENTCATEGORYLIST command handler");

        PkiCommandResponse pkiCommandResponse = null;
        try {
            pkiCommandResponse = listCategory(command);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(entityCategoryNotFoundException.getMessage(), entityCategoryNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final PKIConfigurationServiceException pkiConfigurationServiceException) {
            return prepareErrorMessage(ErrorType.PKI_CONFIGURATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    pkiConfigurationServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), Constants.ERROR_WHILE_LISTING + Constants.SPACE_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CONFIGMANAGEMENTCATEGORYLIST", "ConfigManagementCategoryListHandler",
                "Entity categories listed successfully : ", "List entity categories", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return pkiCommandResponse;

    }

    private PkiCommandResponse listCategory(final PkiPropertyCommand command) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {

        List<EntityCategory> entityCategories;

        if (command.hasProperty(Constants.NAME)) {
            final String categoryName = command.getValueString(Constants.NAME);

            if (ValidationUtils.isNullOrEmpty(categoryName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            EntityCategory entityCategory = new EntityCategory();
            entityCategory.setName(categoryName);

            entityCategory = eServiceRefProxy.getPkiConfigurationManagementService().getCategory(entityCategory);

            entityCategories = new ArrayList<>();
            entityCategories.add(entityCategory);
        } else {
            entityCategories = eServiceRefProxy.getPkiConfigurationManagementService().listAllEntityCategories();
        }

        return buildCommandResponse(entityCategories);
    }

    private PkiCommandResponse buildCommandResponse(final List<EntityCategory> entityCategories) {
        if (CliUtil.isNullOrEmpty(entityCategories)) {
            throw new PKIConfigurationServiceException(Constants.NO_CATEGORY_FOUND_MATCHING_CRITERIA);
        }

        return buildPkiNameMultipleValueCommandResponse(entityCategories);
    }

    private PkiNameMultipleValueCommandResponse buildPkiNameMultipleValueCommandResponse(final List<EntityCategory> entityCategories) {
        final int numberOfColumns = categoryHeader.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation("Following is the list of categor(y/ies)");
        commandResponse.add("Category Name", categoryHeader);

        for (final EntityCategory entityCategory : entityCategories) {
            commandResponse.add(entityCategory.getName(), getCategoryDetails(entityCategory));
        }

        return commandResponse;
    }

    private String[] getCategoryDetails(final EntityCategory entityCategory) {
        final String status = entityCategory.isModifiable() ? "TRUE" : "FALSE";
        final String[] categoryDetails = { status };

        return categoryDetails;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured when listing entity categories {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured when listing entity categories: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

}
