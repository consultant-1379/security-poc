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
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;

/**
 * <p>
 * Handler implementation for EntityManagementImportHandler This provides service to import entity
 * </p>
 *
 * pkiadm entitymgmt|etm --createbulk|-cb -xf file:file.xml
 *
 * @author xsumnan
 */

@CommandType(PkiCommandType.ENTITYMANAGEMENTIMPORT)
@Local(CommandHandlerInterface.class)
public class EntityManagementImportHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    protected static final String[] importFailureHeader = { "Failure reason" };

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
     * Method implementation for EntityManagementImportHandler. Provides service to import entities in bulk
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("ENTITYMANAGEMENTIMPORT command handler");
        final Entities entities;
        PkiCommandResponse commandResponse = null;

        try {
            entities = commandHandlerUtils.getEntitiesFromInputXml(command);

            if (entities == null) {
                return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), Constants.NO_ENTITIES_FOUND_IN_XML);
            }

            eServiceRefProxy.getEntityManagementService().importEntities(entities);
            commandResponse = PkiCommandResponse.message(Constants.ENTITIES_SUCCESSFUL_INFO);

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            commandResponse = prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CRLExtensionException crlExtensionException) {
            logger.debug(crlExtensionException.getMessage(), crlExtensionException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_CRL_EXTENSION.toInt(), crlExtensionException.getMessage());
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            logger.debug(PkiErrorCodes.ENTITY_ALREADY_EXISTS, entityAlreadyExistsException);
            commandResponse = prepareErrorMessage(ErrorType.ENTITY_ALREADY_EXISTS.toInt(), entityAlreadyExistsException.getMessage());
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_CERTIFICATE_NOT_FOUND, entityCategoryNotFoundException);
            commandResponse = prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            commandResponse = prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    entityServiceException);
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_INFO_NOT_FOUND, invalidCRLGenerationInfoException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_CRL_GENERATION_INFO.toInt(), invalidCRLGenerationInfoException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(invalidEntityAttributeException.getMessage(), invalidEntityAttributeException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(invalidEntityCategoryException.getMessage(), invalidEntityCategoryException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidSubjectAltNameExtension invalidSubjectAltNameExtension) {
            logger.debug(invalidSubjectAltNameExtension.getMessage(), invalidSubjectAltNameExtension);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_SUBJECTALTNAME_EXCEPTION.toInt(), invalidSubjectAltNameExtension.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            logger.debug(invalidSubjectException.getMessage(), invalidSubjectException);
            commandResponse = prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            commandResponse = prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), missingMandatoryFieldException.getMessage());
        } catch (final OTPException otpException) {
            logger.debug(otpException.getMessage(), otpException);
            return prepareErrorMessage(ErrorType.OTP_EXCEPTION.toInt(), otpException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            commandResponse = prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.PROFILE_NOT_FOUND);
        } catch (final UnsupportedCRLVersionException unsupportedCRLVersionException) {
            logger.debug(unsupportedCRLVersionException.getMessage(), unsupportedCRLVersionException);
            commandResponse = prepareErrorMessage(ErrorType.UNSUPPORTED_CRL_VERSION.toInt(), unsupportedCRLVersionException.getMessage());
        } catch (CommonRuntimeException commonRuntimeException) {
            commandResponse = prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT, commonRuntimeException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            commandResponse = prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYMANAGEMENTIMPORT", "EntityManagementImportHandler", "Entities imported successfully",
                "Import entities", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while importing the entities {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while importing the entities: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }

}