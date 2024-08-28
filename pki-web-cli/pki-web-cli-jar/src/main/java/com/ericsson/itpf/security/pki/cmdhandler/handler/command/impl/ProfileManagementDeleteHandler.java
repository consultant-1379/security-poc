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

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * <p>
 * Handler implementation for ProfileManagementDeleteHandler, This provides service to delete profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --delete|-d ( --profiletype|-type <> --name|-n <> )| -xf file.xml *
 *
 * @author xsumnan
 */

@CommandType(PkiCommandType.PROFILEMANAGEMENTDELETE)
@Local(CommandHandlerInterface.class)
public class ProfileManagementDeleteHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    private static final String DELETE_SUCCESS = " successfully deleted ";

    @Inject
    Logger logger;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CliUtil cliUtil;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of ProfileManagementDeleteHandler. Processes the command to delete profile in bulk
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        final String profileName = command.getValueString(Constants.NAME);
        final boolean isXmlFileDefined = command.hasProperty(Constants.XML_FILE);

        String commandResponseMsg = PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR;

        try {
            if (isXmlFileDefined) {
                deleteProfiles(command);
                commandResponseMsg = Constants.PROFILES_DETETED_SUCCESSFULLY;
                systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTDELETE", "ProfileManagementDeleteHandler",
                        "Bulk profiles deleted successfully", "Delete profiles", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            } else {
                final String type = command.getValueString(Constants.PROFILE_TYPE).toLowerCase();

                final ProfileType profileType = commandHandlerUtils.getProfileType(type);
                final AbstractProfile profile = getProfileInstance(profileType, profileName);

                eServiceRefProxy.getProfileManagementService().deleteProfile(profile);
                commandResponseMsg = String.format("%s Profile with name %s%s", type, profileName, DELETE_SUCCESS);
                systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTDELETE", "ProfileManagementDeleteHandler", "Profile " + profileName
                        + " deleted successfully", "Delete profile", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }

        } catch (final InvalidProfileException invalidProfileException) {
            logger.debug(invalidProfileException.getMessage(), invalidProfileException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + profileName + Constants.SPACE_STRING
                    + invalidProfileException.getMessage());
        } catch (final ProfileInUseException profileInUseException) {
            logger.debug(PkiErrorCodes.PROFILE_IN_USE, profileInUseException);
            return prepareErrorMessage(ErrorType.PROFILE_INUSE_EXCEPTION.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + profileName + Constants.SPACE_STRING
                    + profileInUseException.getMessage());
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            if (isXmlFileDefined) {
                return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + "profiles " + profileNotFoundException.getMessage());
            } else {
                return prepareErrorMessage(ErrorType.PROFILE_NOT_FOUND_EXCEPTION.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + profileName + Constants.COMMA
                        + profileNotFoundException.getMessage());
            }
        } catch (final ProfileServiceException profileServiceException) {
            return prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + profileName + Constants.SPACE_STRING
                    + PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, profileServiceException);
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.debug(illegalArgumentException.getMessage(), illegalArgumentException);
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), Constants.ERROR_WHILE_DELETING + Constants.SPACE_STRING + profileName + Constants.SPACE_STRING
                    + illegalArgumentException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        return PkiCommandResponse.message(commandResponseMsg);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while deleting the profile {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while deleting the profile: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private void deleteProfiles(final PkiPropertyCommand command) throws IllegalArgumentException, InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {
        final Profiles profiles = getProfilesFromInputXml(command);
        if (profiles != null) {
            eServiceRefProxy.getProfileManagementService().deleteProfiles(profiles);
        } else {
            throw new IllegalArgumentException(Constants.NO_PROFILE_FOUND_IN_XML);
        }
    }

    private Profiles getProfilesFromInputXml(final PkiPropertyCommand command) throws IllegalArgumentException {
        return commandHandlerUtils.getUpdatedProfilesFromInputXml(command);
    }

    private AbstractProfile getProfileInstance(final ProfileType profileType, final String name) throws IllegalArgumentException {
        final AbstractProfile profile = commandHandlerUtils.getProfileInstance(profileType);
        profile.setName(name);

        return profile;
    }
}