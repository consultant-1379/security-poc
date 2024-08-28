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
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;

/**
 * <p>
 * Handler implementation for EntityManagementExportHandler. This provides service to export entity
 * </p>
 *
 * pkiadm entitymgmt|etm --export|-ex ( --entitytype|-type <> --name|-n <> )|(-all|-a)
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.ENTITYMANAGEMENTEXPORT)
@Local(CommandHandlerInterface.class)
public class EntityManagementExportHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    private Logger logger;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    CliUtil cliUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    private boolean additionalFeildsRequired = false;

    /**
     * Method implementation of EntityManagementExportHandler. Processes the command for exporting entities
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTEXPORT command handler");

        PkiCommandResponse commandResponse = null;

        if (command.hasProperty(Constants.ALLFIELDS)) {
            additionalFeildsRequired = true;
        }

        try {
            final String entityName = command.getValueString(Constants.NAME);
            validateEntityName(entityName);
            final EntityType entityType = extractEntityType(command);

            final Entities entities = getBulkExportEntities(entityType, entityName);

            commandResponse = buildCommandResponse(entities);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND);
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(invalidEntityException.getMessage(), invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + Constants.SPACE_STRING + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + Constants.SPACE_STRING + invalidEntityAttributeException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, entityServiceException);
        } catch (final CommandSyntaxException commandSyntaxException) {
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR, commandSyntaxException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTEXPORT", "EntityManagementExportHandler",
                "Entity: " + command.getValueString(Constants.NAME) + " exported successfully", "Export entity", ErrorSeverity.INFORMATIONAL,
                "SUCCESS");
      return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while exporting the entities {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        final String causeMessage = (cause != null) ? cause.getMessage() : "";
        return PkiCommandResponse.message(errorCode, errorMessage, causeMessage);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while exporting the entities: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private EntityType extractEntityType(final PkiPropertyCommand command) {
        String type = null;

        if (command.hasProperty(Constants.ALL)) {
            throw new CommandSyntaxException("EntityType ALL is not supported");
        } else {
            type = command.getValueString(Constants.ENTITY_TYPE).toLowerCase();
        }

        return commandHandlerUtils.getEntityType(type);
    }

    private Entities getBulkExportEntities(final EntityType entityType, final String entityName) throws EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException, IllegalArgumentException {
        Entities entities = null;

        if (entityName == null) {
            if (additionalFeildsRequired) {
                entities = eServiceRefProxy.getEntityManagementService().getEntities(entityType);
            } else {
                entities = eServiceRefProxy.getEntityManagementService().getEntitiesForImport(entityType);
            }
        } else {
            final AbstractEntity entity = getProfileInstance(entityType, entityName);
            entities = getEntityByNameAndType(entity);
        }

        return entities;
    }

    private AbstractEntity getProfileInstance(final EntityType entityType, final String entityName) throws IllegalArgumentException {
        return commandHandlerUtils.getEntityInstance(entityType, entityName);
    }

    @SuppressWarnings("unchecked")
    private <T> Entities getEntityByNameAndType(final AbstractEntity entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        AbstractEntity abstractEntity = null;

        if (additionalFeildsRequired) {
            abstractEntity = eServiceRefProxy.getEntityManagementService().getEntity(entity);
        } else {
            abstractEntity = eServiceRefProxy.getEntityManagementService().getEntityForImport(entity);
        }

        final List<T> entitiesList = new ArrayList<>();
        entitiesList.add((T) abstractEntity);

        return commandHandlerUtils.setEntities(abstractEntity.getType(), entitiesList);
    }

    private PkiCommandResponse buildCommandResponse(final Entities entities) {
        if (entities == null) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND, null);
        }

        return buildPkiCommandResponse(entities);
    }

    private PkiCommandResponse buildPkiCommandResponse(final Entities entities) {
        final String xmlContent = JaxbUtil.getXml(entities, true);
        final String fileIdentifier = CliUtil.generateKey();

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName("exported" + fileIdentifier + ".xml");
        downloadFileHolder.setContentType(Constants.XML_CONTENT_TYPE);
        downloadFileHolder.setContentToBeDownloaded(xmlContent.getBytes());

        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);

        logger.debug("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);

        return commandResponse;
    }

    private static void validateEntityName(final String entityName){
        if(entityName != null && entityName.contains(",")){
            throw new CommandSyntaxException("Comma(,) is not supported in entity name");
            }
        if(entityName != null && entityName.trim().isEmpty()){
            throw new CommandSyntaxException("Entity Name cannot be empty.");
        }
     }
}