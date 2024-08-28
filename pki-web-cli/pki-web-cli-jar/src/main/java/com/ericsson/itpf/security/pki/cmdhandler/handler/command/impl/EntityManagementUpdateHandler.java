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
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * <p>
 * Handler implementation for EntityManagementUpdateHandler, This provides service to update entity
 * </p>
 *
 * pkiadm entitymgmt|etm --update|-u -xf file:file.xml
 *
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.ENTITYMANAGEMENTUPDATE)
@Local(CommandHandlerInterface.class)
public class EntityManagementUpdateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
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
     * Method implementation of EntityManagementUpdateHandler. Processes the command to update CAEntity/entity
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTUPDATE command handler");

        String message = "";
        Entities entities = null;

        /*
         * import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse; import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand; import
         * com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes; import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType; import
         * com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler; import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType; import
         * com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils; import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants; import
         * com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
         */

        final boolean isXmlFileProvided = command.hasProperty(Constants.XML_FILE);

        try {
            if (isXmlFileProvided) {
                entities = commandHandlerUtils.getUpdatedEntitiesFromInputXml(command);
            } else {
                return PkiCommandResponse.message(Constants.INPUT_FILE_MISSING);
            }

            if (entities == null) {
                return PkiCommandResponse.message(Constants.NO_ENTITIES_FOUND_IN_XML);
            }
            message = updateEntry(entities);
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            message = prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CRLExtensionException crlExtensionException) {
            logger.debug(crlExtensionException.getMessage(), crlExtensionException);
            message = prepareErrorMessage(ErrorType.INVALID_CRL_EXTENSION.toInt(), crlExtensionException.getMessage());
        } catch (final CRLGenerationException crlGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION, crlGenerationException);
            message = prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION + crlGenerationException.getMessage());
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            logger.debug(PkiErrorCodes.ENTITY_ALREADY_EXISTS, entityAlreadyExistsException);
            message = prepareErrorMessage(ErrorType.ENTITY_ALREADY_EXISTS.toInt(), PkiErrorCodes.ENTITY_ALREADY_EXISTS);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(entityCategoryNotFoundException.getMessage(), entityCategoryNotFoundException);
            message = prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(),
                    PkiErrorCodes.PROFILE_NOT_FOUND + Constants.SPACE_STRING + entityCategoryNotFoundException.getMessage());
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            message = prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND);
        } catch (final EntityServiceException entityServiceException) {
            message = prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, entityServiceException);
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_INFO_NOT_FOUND, invalidCRLGenerationInfoException);
            message = prepareErrorMessage(ErrorType.INVALID_CRL_GENERATION_INFO.toInt(), invalidCRLGenerationInfoException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            message = prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(invalidEntityCategoryException.getMessage(), invalidEntityCategoryException);
            message = prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            message = prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + Constants.SPACE_STRING + invalidEntityException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            message = prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidSubjectAltNameExtension invalidSubjectAltNameExtension) {
            logger.debug(invalidSubjectAltNameExtension.getMessage(), invalidSubjectAltNameExtension);
            message = prepareErrorMessage(ErrorType.INVALID_SUBJECTALTNAME_EXCEPTION.toInt(), invalidSubjectAltNameExtension.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            logger.debug(invalidSubjectException.getMessage(), invalidSubjectException);
            message = prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            message = prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), missingMandatoryFieldException.getMessage());
        } catch (final OTPException otpException) {
            logger.debug(otpException.getMessage(), otpException);
            message = prepareErrorMessage(ErrorType.OTP_EXCEPTION.toInt(), otpException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            message = prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.PROFILE_NOT_FOUND);
        } catch (final UnsupportedCRLVersionException unsupportedCRLVersionException) {
            logger.debug(unsupportedCRLVersionException.getMessage(), unsupportedCRLVersionException);
            message = prepareErrorMessage(ErrorType.UNSUPPORTED_CRL_VERSION.toInt(), unsupportedCRLVersionException.getMessage());
        } catch (CommonRuntimeException commonRuntimeException) {
            logger.debug(PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT, commonRuntimeException);
            message = prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            message = prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        if (entities != null) {
            systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTUPDATE", "EntityManagementUpdateHandler", "Entities updated successfully",
                    "Update entities", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        }
        return PkiCommandResponse.message(message);
    }

    private String prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while updating the entities: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return CliUtil.buildMessage(errorCode, errorMessage);
    }

    private String prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while updating the entities: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return CliUtil.buildMessage(errorCode, errorMessage);
    }

    @SuppressWarnings("unchecked")
    private String updateEntry(final Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException,
            EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException,
            UnsupportedCRLVersionException {
        String returnMsg = "";

        final List<AbstractEntity> abstractEntities = commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities());

        if (abstractEntities != null && abstractEntities.size() == 1) {
            returnMsg += updateEntry(abstractEntities.get(0));
        } else {
            eServiceRefProxy.getEntityManagementService().updateEntities(entities);
            returnMsg += Constants.ENTITY_GOT_UPDATED_SUCCESSFULLY;
        }

        return returnMsg;
    }

    private String updateEntry(final AbstractEntity abstractEntity) {
        String entityName = "";
        String returnMsg = "";
        String abstractEntityResult = abstractEntity.getType().toString();
        try {
            switch (abstractEntity.getType()) {
                case CA_ENTITY:
                final CAEntity cAEntity = eServiceRefProxy.getEntityManagementService().updateEntity_v1((CAEntity) abstractEntity);
                    entityName = cAEntity.getCertificateAuthority().getName();
                    break;
                case ENTITY:
                final Entity entity = eServiceRefProxy.getEntityManagementService().updateEntity_v1((Entity) abstractEntity);
                    entityName = entity.getEntityInfo().getName();
                    break;
                default:
                    logger.error("There is no object present with entity Type: {}", abstractEntityResult);
                    throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
            }

            returnMsg += "Entity" + " with name:: " + entityName + " " + Constants.IS_SUCCESSFULLY_UPDATED;
        } catch (final EntityServiceException | ProfileNotFoundException | EntityNotFoundException | EntityAlreadyExistsException argumentException) {
            logger.error("Error occured during updation of Entry: {}", argumentException.getMessage());
            throw argumentException;
        } catch (final Exception exception) {
            logger.error("Error occured while updating the entry: {}", exception.getMessage());
            throw exception;
        }
        return returnMsg;
    }
}