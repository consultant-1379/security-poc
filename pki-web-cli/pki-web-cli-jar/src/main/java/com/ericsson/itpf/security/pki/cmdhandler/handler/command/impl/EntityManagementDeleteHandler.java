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

import java.io.IOException;
import java.util.List;

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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * <p>
 * Handler implementation for EntityManagementDeleteHandler. This provides service to delete entity
 * </p>
 *
 * pkiadm entitymgmt|etm --delete|-d ( --entitytype|-type <> --name|-n <> )| -xf file.xml
 *
 * @author xsumnan
 */

@CommandType(PkiCommandType.ENTITYMANAGEMENTDELETE)
@Local(CommandHandlerInterface.class)
public class EntityManagementDeleteHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    private static final String ERROR_WHILE_DELETION = "Error while deleting entity ";

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation for EntityManagementDeleteHandler. Processes the command for deletion of entity
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTDELETE command handler");

        final String entityName = command.getValueString(Constants.NAME);
        String commandResponseMsg = PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR;
        final boolean isXmlFileDefined = command.hasProperty(Constants.XML_FILE);

        try {
            if (isXmlFileDefined) {
                commandResponseMsg = deleteEntity(command);
            } else {
                final String type = command.getValueString(Constants.ENTITY_TYPE).toLowerCase();
                final EntityType entityType = commandHandlerUtils.getEntityType(type);
                commandResponseMsg = deleteEntity(entityName, entityType);
            }
        } catch (final EntityNotFoundException entityNotFoundException) {
            if (isXmlFileDefined) {
                logger.error(PkiErrorCodes.NO_ENTITY_OF_GIVEN_TYPE + Constants.SPACE_STRING + entityNotFoundException.getMessage());
                return prepareErrorMessage(ErrorType.NO_ENTITY_FOUND_MATCHING_CRITERIA.toInt(), PkiErrorCodes.NO_ENTITY_OF_GIVEN_TYPE);
            } else {
                logger.error(PkiErrorCodes.ENTITY_NOT_FOUND + Constants.SPACE_STRING + entityNotFoundException.getMessage());
                return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            }
        } catch (final CommonRuntimeException commonRuntimeException) {
            return prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT, commonRuntimeException);
        } catch (final EntityInUseException entityInUseException) {
            logger.debug(ERROR_WHILE_DELETION + entityInUseException.getMessage(), entityInUseException);
            return prepareErrorMessage(ErrorType.ENTITY_IN_USE.toInt(), ERROR_WHILE_DELETION + entityInUseException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), ERROR_WHILE_DELETION + PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
        entityServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        }catch (final InvalidEntityException invalidEntityException) {
            logger.debug(invalidEntityException.getMessage(), invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), ERROR_WHILE_DELETION + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), ERROR_WHILE_DELETION + invalidEntityAttributeException.getMessage());
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), ERROR_WHILE_DELETION + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTDELETE", "EntityManagementDeleteHandler", "Entity: " + entityName
                + " deleted successfully", "Delete entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return PkiCommandResponse.message(commandResponseMsg);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while deleting the entities {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while deleting the entities: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));
    }

    private String deleteEntity(final PkiPropertyCommand command) throws EntityInUseException, EntityNotFoundException, EntityServiceException,
            IllegalArgumentException, InvalidEntityException, InvalidEntityAttributeException, IOException {
        final Entities entities = getEntitiesFromInputXml(command);

        if (null == entities) {
            return "Error: " + (PkiWebCliException.ERROR_CODE_START_INT + ErrorType.ENTITY_NOT_FOUND.toInt()) + Constants.SPACE_STRING + Constants.NO_ENTITIES_FOUND_IN_SYSTEM;
        }

        return deleteEntity(entities);
    }

    private Entities getEntitiesFromInputXml(final PkiPropertyCommand command) throws IOException {
        return commandHandlerUtils.getUpdatedEntitiesFromInputXml(command);
    }

    @SuppressWarnings("unchecked")
    private String deleteEntity(final Entities entities) throws EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        String returnMsg = Constants.EMPTY_STRING;

        final List<AbstractEntity> abstractEntities = commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities());

        if (abstractEntities != null && abstractEntities.size() == 1) {
            final AbstractEntity abstractEntity = abstractEntities.get(0);
            returnMsg += deleteEntry(abstractEntity);
        } else {
            eServiceRefProxy.getEntityManagementService().deleteEntities(entities);
            returnMsg += Constants.ENTITY_DELETED_SUCCESSFULLY;
        }

        return returnMsg;
    }

    private String deleteEntity(final String entityName, final EntityType entityType) throws EntityInUseException, EntityNotFoundException, EntityServiceException,
            IllegalArgumentException, InvalidEntityException, InvalidEntityAttributeException {
        String returnMsg = Constants.EMPTY_STRING;

        if (entityName == null || entityType == null) {
            returnMsg += "Unable to delete the entity. EntityName and entityType is mandatory Parameters";
        } else {

            final AbstractEntity abstractEntity = commandHandlerUtils.getEntityInstance(entityType, entityName);

            returnMsg += deleteEntry(abstractEntity);
        }

        return returnMsg;
    }

    private String deleteEntry(final AbstractEntity abstractEntity) throws EntityInUseException, EntityNotFoundException, EntityServiceException,
            IllegalArgumentException, InvalidEntityException, InvalidEntityAttributeException {
        String entityName = null;
        String returnMsg = Constants.EMPTY_STRING;
        String abstractEntityResult = abstractEntity.getType().toString();
        switch (abstractEntity.getType()) {
            case CA_ENTITY:
                eServiceRefProxy.getEntityManagementService().deleteEntity((CAEntity) abstractEntity);
                entityName = ((CAEntity) abstractEntity).getCertificateAuthority().getName();
                break;
            case ENTITY:
                eServiceRefProxy.getEntityManagementService().deleteEntity((Entity) abstractEntity);
                entityName = ((Entity) abstractEntity).getEntityInfo().getName();
                break;
            default:
                logger.error("There is no object present with entity Type: {} " , abstractEntityResult);
                throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

        returnMsg += "Entity" + " with name:: " + entityName + Constants.SUCCESSFULLY_DELETED;

        return returnMsg;
    }
}
