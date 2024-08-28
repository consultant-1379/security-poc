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
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * <p>
 * Handler implementation for EntityManagementListHandler This provides service to list entity
 * </p>
 *
 * pkiadm entitymgmt|etm --list|-l ( --entitytype|-type <> (--name|-n <> | --category|-cat <>) )
 *
 * @author xsumnan
 */

@CommandType(PkiCommandType.ENTITYMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class EntityManagementListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation for EntityManagementListHandler. Processes the command to list entities from service.
     *
     * @param command
     *
     * @return pkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTLIST command handler");

        PkiCommandResponse pkiCommandResponse = null;
        Entities entities = null;
        try {

            final EntityType entityType = extractEntityType(command);

            if (command.hasProperty(Constants.NAME)) {
                final String entityName = command.getValueString(Constants.NAME);
                if (ValidationUtils.isNullOrEmpty(entityName)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
                }

                final AbstractEntity abstractEntity = commandHandlerUtils.getEntityInstance(entityType, entityName);
                entities = getEntityByNameAndType(abstractEntity);
                pkiCommandResponse = buildCommandResponse(entities);

            } else if (command.hasProperty(Constants.CATEGORY)) {

                if (entityType.equals(EntityType.CA_ENTITY)) {

                    return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_EXCEPTION.toInt(), PkiErrorCodes.CATEGORY_IS_NOT_APPLICABLE);
                }
                final String entityCategoryName = command.getValueString(Constants.CATEGORY);

                if (ValidationUtils.isNullOrEmpty(entityCategoryName)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CATEGORY_NAME_CANNOT_BE_NULL_OR_EMPTY);
                }

                final EntityCategory entityCategory = new EntityCategory();
                entityCategory.setName(entityCategoryName);
                entities = getEntitiesByCategoryAndType(entityType, entityCategory);
                pkiCommandResponse = buildPkiCategoryCommandResponse(entities);

            } else {
                entities = eServiceRefProxy.getEntityManagementService().getEntitiesForImport(entityType);
                pkiCommandResponse = buildCommandResponse(entities);
            }

        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(entityCategoryNotFoundException.getMessage(), entityCategoryNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND + entityCategoryNotFoundException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, entityServiceException);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(PkiErrorCodes.CATEGORY_IS_NOT_APPLICABLE, invalidEntityCategoryException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final CommandSyntaxException commandSyntaxException) {
            logger.debug(commandSyntaxException.getMessage(), commandSyntaxException);
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), commandSyntaxException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
           return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
              } catch (Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), Constants.ERROR_WHILE_LISTING + Constants.SPACE_STRING + exception.getMessage(), exception);

        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTLIST", "EntityManagementListHandler", "Entities fetched successfully of type "
                + extractEntityType(command), "List entities", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final Throwable cause) {
        logger.error("Error: {} occured while listing the entities {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return PkiCommandResponse.message(errorCode, CliUtil.buildMessage(errorCode, errorString), cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the entities: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private EntityType extractEntityType(final PkiPropertyCommand command) throws CommandSyntaxException {
        String type = null;

        if (command.hasProperty(Constants.ALL)) {
            throw new CommandSyntaxException("EntityType ALL is not supported");
        } else {
            type = command.getValueString(Constants.ENTITY_TYPE).toLowerCase();
        }

        return commandHandlerUtils.getEntityType(type);
    }

    private <T extends AbstractEntity> Entities getEntityByNameAndType(final T abstractEntity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        final T entity = eServiceRefProxy.getEntityManagementService().getEntity(abstractEntity);

        final List<T> entitiesList = new ArrayList<>();
        entitiesList.add((T) entity);

        return commandHandlerUtils.setEntities(abstractEntity.getType(), entitiesList);
    }

    private <T extends AbstractEntity> Entities getEntitiesByCategoryAndType(final EntityType entityType, final EntityCategory entityCategory) throws EntityCategoryNotFoundException,
            EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException {
        final List<Entity> entityList = eServiceRefProxy.getEntityManagementService().getEntitiesByCategory(entityCategory);

        return commandHandlerUtils.setEntities(entityType, entityList);
    }

    private PkiNameMultipleValueCommandResponse buildCommandResponse(final Entities entities) throws EntityNotFoundException {
        if (null == entities) {
            throw new EntityNotFoundException(Constants.NO_ENTITIES_FOUND_IN_SYSTEM);
        }
        final List<AbstractEntity> abstractEntities = commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities());

        if (ValidationUtils.isNullOrEmpty(abstractEntities)) {
            throw new EntityNotFoundException(" with sepcified option");
        }
        return buildPkiCommandResponse(entities);
    }

    private PkiNameMultipleValueCommandResponse buildPkiCommandResponse(final Entities entities) {
        final int numberOfColumns = Constants.ENTITY_HEADER.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation(Constants.LIST_OF_ENTITIES);
        commandResponse.add(Constants.ID, Constants.ENTITY_HEADER);

        if (entities.getEntities() != null) {
            for (final Entity entity : entities.getEntities()) {
                final String entityName = entity.getEntityInfo().getName();
                final long id = entity.getEntityInfo().getId();
                final EntityStatus entityStatus = entity.getEntityInfo().getStatus();
                final String[] entityDetails = { entityName, entity.getType().toString(), entityStatus.toString() };
                commandResponse.add(String.valueOf(id), entityDetails);
            }
        }

        if (entities.getCAEntities() != null) {
            for (final CAEntity caEntity : entities.getCAEntities()) {
                final String caEntityName = caEntity.getCertificateAuthority().getName();
                final long id = caEntity.getCertificateAuthority().getId();
                final CAStatus caStatus = caEntity.getCertificateAuthority().getStatus();
                final String[] caEntityDetails = { caEntityName, caEntity.getType().toString(), caStatus.toString() };
                commandResponse.add(String.valueOf(id), caEntityDetails);
            }
        }

        return commandResponse;
    }

    private PkiNameMultipleValueCommandResponse buildPkiCategoryCommandResponse(final Entities entities) {
        final int numberOfColumns = Constants.ENTITY_CATEGORY_HEADER.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);
        commandResponse.setAdditionalInformation(Constants.LIST_OF_ENTITIES);
        commandResponse.add(Constants.ID, Constants.ENTITY_CATEGORY_HEADER);
        if (entities.getEntities() != null) {
            for (final Entity entity : entities.getEntities()) {
                final String entityName = entity.getEntityInfo().getName();
                final String entityCategory = entity.getCategory().getName();
                final Boolean isModifiable = entity.getCategory().isModifiable();
                final long id = entity.getEntityInfo().getId();
                final EntityStatus entityStatus = entity.getEntityInfo().getStatus();
                final String[] entityDetails = { entityName, entityCategory, isModifiable.toString().toUpperCase(), entityStatus.toString() };
                commandResponse.add(String.valueOf(id), entityDetails);
            }
        }

        return commandResponse;
    }

}