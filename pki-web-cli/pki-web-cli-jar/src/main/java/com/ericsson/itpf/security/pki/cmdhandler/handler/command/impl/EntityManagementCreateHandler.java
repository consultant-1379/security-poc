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
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;

/**
 * <p>
 * Handler implementation for EntityManagementCreateHandler. This provides service to create entity
 * </p>
 *
 * pkiadm entitymgmt|etm --create|-c -xf file:file.xml
 *
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.ENTITYMANAGEMENTCREATE)
@Local(CommandHandlerInterface.class)
public class EntityManagementCreateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

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
     * Method implementation of EntityManagementCreateHandler. Processes the command to create CAEntity/entity
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTCREATE command handler");

        String message = Constants.EMPTY_STRING;

        Entities entities = null;

        final boolean isXmlFileDefined = command.hasProperty(Constants.XML_FILE);

        try {

            if (isXmlFileDefined) {
                entities = commandHandlerUtils.getEntitiesFromInputXml(command);
            } else {

                return prepareErrorMessage(ErrorType.INVALID_INPUT_XML_FILE.toInt(), Constants.INPUT_FILE_MISSING);
            }

            message = createEntity(entities);

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CRLExtensionException crlExtensionException) {
            logger.debug(crlExtensionException.getMessage(), crlExtensionException);
            return prepareErrorMessage(ErrorType.INVALID_CRL_EXTENSION.toInt(), crlExtensionException.getMessage());
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            logger.debug(PkiErrorCodes.ENTITY_ALREADY_EXISTS, entityAlreadyExistsException);
            return prepareErrorMessage(ErrorType.ENTITY_ALREADY_EXISTS.toInt(), PkiErrorCodes.ENTITY_ALREADY_EXISTS);
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(entityCategoryNotFoundException.getMessage(), entityCategoryNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, entityServiceException);
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_INFO_NOT_FOUND, invalidCRLGenerationInfoException);
            return prepareErrorMessage(ErrorType.INVALID_CRL_GENERATION_INFO.toInt(), invalidCRLGenerationInfoException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(invalidEntityCategoryException.getMessage(), invalidEntityCategoryException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidSubjectAltNameExtension invalidSubjectAltNameExtension) {
            logger.debug(invalidSubjectAltNameExtension.getMessage(), invalidSubjectAltNameExtension);
            return prepareErrorMessage(ErrorType.INVALID_SUBJECTALTNAME_EXCEPTION.toInt(), invalidSubjectAltNameExtension.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            logger.debug(invalidSubjectException.getMessage(), invalidSubjectException);
            return prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
        	logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), missingMandatoryFieldException.getMessage());
        } catch (final OTPException otpException) {
            logger.debug(otpException.getMessage(), otpException);
            return prepareErrorMessage(ErrorType.OTP_EXCEPTION.toInt(), otpException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
        	logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.PROFILE_NOT_FOUND);
        } catch (final UnsupportedCRLVersionException unsupportedCRLVersionException) {
            logger.debug(unsupportedCRLVersionException.getMessage(), unsupportedCRLVersionException);
            return prepareErrorMessage(ErrorType.UNSUPPORTED_CRL_VERSION.toInt(), unsupportedCRLVersionException.getMessage());
        } catch (CommonRuntimeException commonRuntimeException) {
            return prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT, commonRuntimeException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage());
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTCREATE", "EntityManagementCreateHandler", "Entity created successfully",
                "Create entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return PkiCommandResponse.message(message);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while creating the entities {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while creating the entities: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    @SuppressWarnings("unchecked")
    private String createEntity(final Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityServiceException,
            EntityCategoryNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException {

        String returnMsg = Constants.EMPTY_STRING;
        List<AbstractEntity> abstractEntities = null;

        if (entities == null) {
            return CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), Constants.NO_ENTITIES_FOUND, Constants.EMPTY_STRING);
        }

        abstractEntities = commandHandlerUtils.getAllEntries(entities.getCAEntities(), entities.getEntities());

        if (abstractEntities == null) {
            return String.format("%d %s", PkiWebCliException.ERROR_CODE_START_INT + ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR);
        }

        if (abstractEntities.size() == 1) {
            eServiceRefProxy.getEntityManagementService().createEntity_v1(abstractEntities.get(0));

            returnMsg += Constants.ENTITY_SUCCESSFUL_INFO;
        } else {
            returnMsg += Constants.TRY_IMPORT_COMMAND_FOR_THAN_ONE_ENTITY;
        }
        return returnMsg;
    }

}