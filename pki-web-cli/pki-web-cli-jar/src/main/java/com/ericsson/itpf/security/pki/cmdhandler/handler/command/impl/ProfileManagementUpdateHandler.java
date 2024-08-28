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
 * Handler implementation for ProfileManagementUpdateHandler. This provides service to update profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --update|-u -xf file:file.xml
 *
 * @author xsumnan
 *
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTUPDATE)
@Local(CommandHandlerInterface.class)
public class ProfileManagementUpdateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of ProfileManagementUpdateHandler for updating profile. Processes the command to update profile.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("PROFILEMANAGEMENTUPDATE command handler");

        String message = "";
        Profiles profiles = null;

        try {
            final boolean isXmlFileDefined = command.hasProperty(Constants.XML_FILE);
            if (isXmlFileDefined) {
                profiles = commandHandlerUtils.getUpdatedProfilesFromInputXml(command);
            } else {
                return PkiCommandResponse.message(prepareErrorMessage(ErrorType.INVALID_INPUT_XML_FILE.toInt(), Constants.INPUT_FILE_MISSING));
            }
            message = updateProfile(profiles);
            if (profiles != null) {
                systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTUPDATE", "ProfileManagementUpdateHandler",
                        "Profiles updated successfully", "Update profiles", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            message = prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (CertificateExtensionException certificateExtensionException) {
            logger.debug(certificateExtensionException.getMessage(), certificateExtensionException);
            message = prepareErrorMessage(ErrorType.CERTIFICATE_EXTENTION_EXCEPTION.toInt(), certificateExtensionException.getMessage());
        } catch (final EntityCategoryNotFoundException entityCategoryNotFoundException) {
            logger.debug(PkiErrorCodes.CATEGORY_IS_NOT_APPLICABLE, entityCategoryNotFoundException);
            message = prepareErrorMessage(ErrorType.ENTITY_CATEGORY_NOT_FOUND_EXCEPTION.toInt(), entityCategoryNotFoundException.getMessage());
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidCAException);
            message = prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidEntityCategoryException invalidEntityCategoryException) {
            logger.debug(PkiErrorCodes.CATEGORY_IS_NOT_APPLICABLE, invalidEntityCategoryException);
            message = prepareErrorMessage(ErrorType.INVALID_ENTITY_CATEGORY_EXCEPTION.toInt(), invalidEntityCategoryException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            message = prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            logger.debug(invalidProfileAttributeException.getMessage(), invalidProfileAttributeException);
            message = prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(), invalidProfileAttributeException.getMessage());
        } catch (final InvalidSubjectException invalidSubjectException) {
            logger.debug(invalidSubjectException.getMessage(), invalidSubjectException);
            message = prepareErrorMessage(ErrorType.INVALID_SUBJECT_EXCEPTION.toInt(), invalidSubjectException.getMessage());
        } catch (final MissingMandatoryFieldException mandatoryFieldException) {
            logger.debug(mandatoryFieldException.getMessage(), mandatoryFieldException);
            message = prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), mandatoryFieldException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            message = prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), profileNotFoundException.getMessage());

        } catch (final ProfileAlreadyExistsException profileAlreadyExistsException) {
            message = prepareErrorMessage(ErrorType.PROFILE_ALREADY_EXIST_EXCEPTION.toInt(), PkiErrorCodes.PROFILE_ALREADY_EXIST_EXCEPTION);
        } catch (final CANotFoundException caNotFoundException) {
            message = prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final ProfileServiceException profileServiceException) {
            if (profileServiceException.getMessage().contains("Profile modifiable flag is disabled!!")) {
                message = "Profile modifiable flag is disabled!!";
            } else {
                message = prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT + Constants.SPACE_STRING
                        + PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY);
            }
        } catch (final UnSupportedCertificateVersion unSupportedCertificateVersion) {
            logger.debug(unSupportedCertificateVersion.getMessage(), unSupportedCertificateVersion);
            message = prepareErrorMessage(ErrorType.UNSUPPORTED_CERTIFICATE_VERSION.toInt(), unSupportedCertificateVersion.getMessage());
        } catch (final CommonRuntimeException commonRuntimeException) {
            message = prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(),
                    PkiErrorCodes.PLEASE_SEE_THE_ONLINE_HELP_FOR_THE_CORRECT_FORMAT + Constants.SPACE_STRING + commonRuntimeException.getMessage());
            logger.info(message);
        } catch (final IllegalArgumentException illegalArgumentException) {
            message = prepareErrorMessage(ErrorType.INVALID_INPUT_XML_FILE.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.SPACE_STRING + illegalArgumentException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            message = prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }

        return PkiCommandResponse.message(message);
    }

    private String prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {}occured while updating the profiles {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return CliUtil.buildMessage(errorCode, errorMessage);
    }

    private String prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {}  occured while updating the profiles: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return CliUtil.buildMessage(errorCode, errorMessage);
    }

    private String updateProfile(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {
        if (profiles == null) {
            return Constants.NO_PROFILE_FOUND_IN_XML;
        }

        return modifyProfile(profiles);
    }

    @SuppressWarnings("unchecked")
    private String modifyProfile(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {
        String returnMsg = "";
        List<AbstractProfile> abstractProfiles = null;

        abstractProfiles = commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles());

        if (abstractProfiles != null && abstractProfiles.size() == 1) {
            logger.info("ENTER INTO UPDATE PROFILE IN WEBCLi");
            final AbstractProfile abstractProfile = eServiceRefProxy.getProfileManagementService().updateProfile(abstractProfiles.get(0));

            returnMsg += abstractProfile.getClass().getSimpleName() + " ID: " + abstractProfile.getId() + ", Name: " + abstractProfile.getName() + " " + Constants.IS_SUCCESSFULLY_UPDATED;
        } else {
            eServiceRefProxy.getProfileManagementService().updateProfiles(profiles);
            returnMsg += Constants.PROFILES_UPDATED_SUCCESSFULLY;
        }

        return returnMsg;
    }
}