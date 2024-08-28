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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * <p>
 * Handler implementation for ProfileManagementCreateHandler This provides service to create profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --create|-c -xf file:file.xml
 *
 * @author xsumnan on 29/03/2015.
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTCREATE)
@Local(CommandHandlerInterface.class)
public class ProfileManagementCreateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

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
     * Method implementation of ProfileManagementCreateHandler. Processes the command to import/create profile
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("PROFILEMANAGEMENTCREATE command handler");

        Profiles profiles = null;

        final boolean isXmlFileDefined = command.hasProperty(Constants.XML_FILE);

        try {

            if (isXmlFileDefined) {
                profiles = commandHandlerUtils.getProfilesFromInputXml(command);
            } else {
                logger.debug(Constants.INPUT_FILE_MISSING);
                return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND.toInt(), Constants.INPUT_FILE_MISSING);
            }
            if (profiles != null) {
                systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTCREATE", "ProfileManagementCreateHandler",
                        "Profiles created successfully", "Create profile", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }
            return createProfile(profiles);

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final ProfileAlreadyExistsException profileAlreadyExistsException) {
            logger.debug(PkiErrorCodes.PROFILE_ALREADY_EXIST_EXCEPTION, profileAlreadyExistsException);
            return prepareErrorMessage(ErrorType.PROFILE_ALREADY_EXISTS.toInt(), PkiErrorCodes.PROFILE_ALREADY_EXIST_EXCEPTION);
        } catch (final CANotFoundException caNotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND.toInt(), caNotFoundException.getMessage());
        } catch (final CertificateExtensionException certificateExtensionException) {
            logger.debug(certificateExtensionException.getMessage(), certificateExtensionException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXTENTION_EXCEPTION.toInt(), certificateExtensionException.getMessage());
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(entityCategoryNotFoundException.getMessage(), entityCategoryNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(invalidEntityCategoryException.getMessage(), invalidEntityCategoryException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            logger.debug(invalidProfileAttributeException.getMessage(), invalidProfileAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(), invalidProfileAttributeException.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            logger.debug(invalidSubjectException.getMessage(), invalidSubjectException);
            return prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException mandatoryFieldException) {
            logger.debug(mandatoryFieldException.getMessage(), mandatoryFieldException);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), mandatoryFieldException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), profileNotFoundException.getMessage());
        } catch (final ProfileServiceException profileServiceException) {
            return prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, profileServiceException);
        } catch (final UnSupportedCertificateVersion unSupportedCertificateVersion) {
            logger.debug(unSupportedCertificateVersion.getMessage(), unSupportedCertificateVersion);
            return prepareErrorMessage(ErrorType.UNSUPPORTED_CERTIFICATE_VERSION.toInt(), unSupportedCertificateVersion.getMessage());
        } catch (final CommonRuntimeException commonRuntimeException) {
            logger.debug(PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT, commonRuntimeException);
            return prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage());
        }

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final Throwable cause) {
        logger.error("Error: {}  occured while listing the entities {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return PkiCommandResponse.message(errorCode, CliUtil.buildMessage(errorCode, errorString), cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the entities: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }

    @SuppressWarnings("unchecked")
    private PkiCommandResponse createProfile(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException,
            InvalidCAException, InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileAlreadyExistsException, ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        List<AbstractProfile> abstractProfiles = null;

        if (profiles == null) {
            return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND.toInt(), Constants.NO_PROFILE_FOUND_IN_XML);
        }

        abstractProfiles = commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles());

        if (abstractProfiles != null && abstractProfiles.size() == 1) {
            eServiceRefProxy.getProfileManagementService().createProfile(abstractProfiles.get(0));

            return PkiCommandResponse.message(Constants.PROFILES_GOT_CREATED_SUCCESSFULLY);
        } else {
            return prepareErrorMessage(ErrorType.INVALID_INPUT_XML_FILE.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT);

        }

    }
}