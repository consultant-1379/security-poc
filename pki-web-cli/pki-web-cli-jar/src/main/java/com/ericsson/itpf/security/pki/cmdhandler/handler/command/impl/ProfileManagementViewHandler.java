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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.*;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * <p>
 * Handler implementation for ProfileManagementViewHandler, This provides service to View profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --view|-v ( --profiletype|-type <> --name|-n <> )
 *
 * @author tcschsa
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTVIEW)
@Local(CommandHandlerInterface.class)
public class ProfileManagementViewHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    private TrustProfileViewCommandResponse trustProfileViewCommandResponse;

    @Inject
    private CertificateProfileViewCommandResponse certificateProfileViewCommandResponse;

    @Inject
    private EntityProfileViewCommandResponse entityProfileViewCommandResponse;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;
    /**
     * Method implementation for ProfileManagementViewHandler. Processes the command to view profiles
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.debug("PROFILEMANAGEMENTVIEW command handler");
        boolean name= command.hasProperty(Constants.NAME);
        logger.debug("command has propety :: {}" , name);

        PkiCommandResponse pkiCommandResponse = null;
        try {
            final String profileName = command.getValueString(Constants.NAME);
            validateProfileName(profileName);
            final ProfileType profileType = extractProfileType(command);
            pkiCommandResponse = getProfileDetails(profileType, profileName);
            systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTVIEW", "ProfileManagementViewHandler", "Profile " + profileName
                    + " fetched successfully of type: " + profileType.name(), "View profile", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final ProfileNotFoundException profileNotFoundException) {
            return prepareErrorMessage(ErrorType.NO_PROFILE_FOUND_MATCHING_CRITERIA.toInt(), PkiErrorCodes.NO_PROFILE_OF_GIVEN_TYPE);
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(), invalidProfileAttributeException.getMessage());
        } catch (final InvalidProfileException invalidProfileException) {
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), invalidProfileException.getMessage());
        } catch (final ProfileServiceException profileServiceException) {
            return prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    profileServiceException);
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), missingMandatoryFieldException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + Constants.SPACE_STRING + illegalArgumentException.getMessage());
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

    private PkiCommandResponse getProfileDetails(final ProfileType profileType, final String profileName) throws IllegalArgumentException, InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException {

        switch (profileType) {

            case CERTIFICATE_PROFILE:

                CertificateProfile certificateProfile = new CertificateProfile();
                certificateProfile.setName(profileName);
                certificateProfile = eServiceRefProxy.getProfileManagementService().getProfile(certificateProfile);
                return certificateProfileViewCommandResponse.buildCommandResponseForCertificateProfile(certificateProfile);

            case ENTITY_PROFILE:
                EntityProfile entityProfile = new EntityProfile();
                entityProfile.setName(profileName);
                entityProfile = eServiceRefProxy.getProfileManagementService().getProfile(entityProfile);
                return entityProfileViewCommandResponse.buildCommandResponseForEntityProfile(entityProfile);

            case TRUST_PROFILE:
                TrustProfile trustProfile = new TrustProfile();
                trustProfile.setName(profileName);
                trustProfile = eServiceRefProxy.getProfileManagementService().getProfile(trustProfile);
                return trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(trustProfile);

            default:
                logger.error("There is no object present with profile Type");
                throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while getting the profiles {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while getting the profiles: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
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
   private static void validateProfileName(final String profileName){
       if(profileName != null && profileName.contains(",")){
           throw new CommandSyntaxException("Comma(,) is not supported in profile name");
           }
    }
}
