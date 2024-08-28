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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * <p>
 * Handler implementation for ProfileManagementListHandler, This provides service to list profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --list|-l ( --profiletype|-type <> --name|-n <> )|(-all|-a)
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class ProfileManagementListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    final String[] PROFILEHEADER = { "Profile Name", "Profile Type" };

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
     * Method implementation for ProfileManagementListHandler. Processes the command to list profiles
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("PROFILEMANAGEMENTLIST command handler");

        Profiles profiles = null;
        PkiCommandResponse pkiCommandResponse = null;

        try {
            final String name = command.getValueString(Constants.NAME);
            final ProfileType profileType = extractProfileType(command);

            profiles = getListOfProfiles(profileType, name);

            pkiCommandResponse = buildCommandResponse(profiles);
            systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTLIST", "ProfileManagementListHandler",
                    "Profiles fetched successfully based on name: " + name + " and profile type: " + profileType, "List profiles",
                    ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final ProfileNotFoundException profileNotFoundException) {
            return prepareErrorMessage(ErrorType.NO_PROFILE_FOUND_MATCHING_CRITERIA.toInt(), PkiErrorCodes.NO_PROFILE_OF_GIVEN_TYPE);
        } catch (final InvalidProfileException invalidProfileException) {
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(), invalidProfileAttributeException.getMessage());
        } catch (final ProfileServiceException profileServiceException) {
            return prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    profileServiceException);
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), missingMandatoryFieldException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + illegalArgumentException.getMessage());
        } catch (final CommandSyntaxException commandSyntaxException) {
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), commandSyntaxException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while listing the profiles {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error:{} occured while listing the profiles: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private ProfileType extractProfileType(final PkiPropertyCommand command) throws CommandSyntaxException, IllegalArgumentException {
        String type = null;

        if (command.hasProperty(Constants.ALL)) {
            throw new CommandSyntaxException("ProfileType ALL is not supported");
        } else {
            type = command.getValueString(Constants.PROFILE_TYPE).toLowerCase();
        }

        return commandHandlerUtils.getProfileType(type);
    }

    private Profiles getListOfProfiles(final ProfileType profileType, final String profileName) throws IllegalArgumentException, InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException {
        Profiles profiles = null;

        if (profileName == null) {
            profiles = eServiceRefProxy.getProfileManagementService().exportProfiles(profileType);
        } else {
            final AbstractProfile profile = getProfileInstance(profileType, profileName);
            profiles = getProfileByNameAndType(profile);
        }

        return profiles;
    }

    private AbstractProfile getProfileInstance(final ProfileType profileType, final String name) throws IllegalArgumentException {
        final AbstractProfile profile = commandHandlerUtils.getProfileInstance(profileType);
        profile.setName(name);

        return profile;
    }

    @SuppressWarnings("unchecked")
    private <T> Profiles getProfileByNameAndType(final AbstractProfile profile) throws IllegalArgumentException, InvalidProfileException, InvalidProfileAttributeException, ProfileNotFoundException,
            ProfileServiceException, MissingMandatoryFieldException {

        final AbstractProfile abstractProfile = eServiceRefProxy.getProfileManagementService().getProfile(profile);

        final List<T> profilesList = new ArrayList<>();
        profilesList.add((T) abstractProfile);

        return  commandHandlerUtils.setProfiles(abstractProfile.getType(), profilesList);
    }

    @SuppressWarnings("unchecked")
    private PkiNameMultipleValueCommandResponse buildCommandResponse(final Profiles profiles) throws ProfileNotFoundException {
        if (profiles == null) {
            throw new ProfileNotFoundException(Constants.NO_PROFILE_FOUND_IN_SYSTEM);
        }

        final List<AbstractProfile> abstractProfiles = commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles());

        if (ValidationUtils.isNullOrEmpty(abstractProfiles)) {
            throw new ProfileNotFoundException(Constants.NO_PROFILE_FOUND_IN_SYSTEM);
        }

        return buildPkiCommandResponse(abstractProfiles);
    }

    private PkiNameMultipleValueCommandResponse buildPkiCommandResponse(final List<AbstractProfile> abstractProfiles) {
        final int numberOfColumns = PROFILEHEADER.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation(Constants.LIST_OF_PROFILES);
        commandResponse.add(Constants.ID, PROFILEHEADER);

        for (final AbstractProfile abstractProfile : abstractProfiles) {
            final long id = abstractProfile.getId();
            commandResponse.add(String.valueOf(id), getProfilesDetails(abstractProfile));
        }

        return commandResponse;
    }

    private String[] getProfilesDetails(final AbstractProfile profile) {
        final String[] profileDetails = { profile.getName(), profile.getType() + Constants.EMPTY_STRING };
        return profileDetails;
    }
}