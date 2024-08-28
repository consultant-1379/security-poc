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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * <p>
 * Handler implementation for ProfileManagementImportHandler This provides service to import profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --createbulk|-cb -xf file:file.xml
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTIMPORT)
@Local(CommandHandlerInterface.class)
public class ProfileManagementImportHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of ProfileManagementImportHandler. Processes the command to import/create profiles in bulk
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("PROFILEMANAGEMENTIMPORT command handler");

        Profiles profiles = null;
        PkiCommandResponse commandResponse = null;

        try {

            profiles = commandHandlerUtils.getProfilesFromInputXml(command);
            if (profiles == null) {
                return PkiCommandResponse.message(Constants.NO_PROFILES_FOUND);
            }

            eServiceRefProxy.getProfileManagementService().importProfiles(profiles);
            commandResponse = PkiCommandResponse.message(Constants.BULK_SUCCESSFUL_INFO);
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            commandResponse = prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final ProfileAlreadyExistsException profileAlreadyExistsException) {
            commandResponse = prepareErrorMessage(ErrorType.PROFILE_ALREADY_EXISTS.toInt(), PkiErrorCodes.PROFILE_ALREADY_EXIST_EXCEPTION);
        } catch (final CANotFoundException caNotFoundException) {
            commandResponse = prepareErrorMessage(ErrorType.CA_NOT_FOUND.toInt(), caNotFoundException.getMessage());
        } catch (final CertificateExtensionException certificateExtensionException) {
            commandResponse = prepareErrorMessage(ErrorType.CERTIFICATE_EXTENTION_EXCEPTION.toInt(), certificateExtensionException.getMessage());
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            commandResponse = prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final InvalidCAException invalidCAException) {
            commandResponse = prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            commandResponse = prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            commandResponse = prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(), invalidProfileAttributeException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            commandResponse = prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            commandResponse = prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException mandatoryFieldException) {
            commandResponse = prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), mandatoryFieldException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            commandResponse = prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), profileNotFoundException.getMessage());
        } catch (final ProfileServiceException profileServiceException) {
            commandResponse = prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    profileServiceException);
        } catch (final UnSupportedCertificateVersion unSupportedCertificateVersion) {
            commandResponse = prepareErrorMessage(ErrorType.UNSUPPORTED_CERTIFICATE_VERSION.toInt(), unSupportedCertificateVersion.getMessage());
        } catch (final CommonRuntimeException commonRuntimeException) {
            commandResponse = prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            commandResponse = prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
            systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTIMPORT", "ProfileManagementImportHandler",
                    "Bulk profiles imported successfully", "Import bulk profiles", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while import the profiles {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while import the profiles: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }
}