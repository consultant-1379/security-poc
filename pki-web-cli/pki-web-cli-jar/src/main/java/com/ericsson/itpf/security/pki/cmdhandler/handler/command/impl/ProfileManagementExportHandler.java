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
import com.ericsson.itpf.security.pki.cmdhandler.util.*;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * <p>
 * Handler implementation for ProfileManagementExportHandler This provides service to export profile
 * </p>
 *
 * pkiadm profilemgmt|pfm --export|-ex ( --profiletype|-type <> --name|-n <> )|(-all|-a)
 *
 * @author xsumnan
 */
@CommandType(PkiCommandType.PROFILEMANAGEMENTEXPORT)
@Local(CommandHandlerInterface.class)
public class ProfileManagementExportHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    CliUtil cliUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    private boolean additionalFeildsRequired = false;

    /**
     * Method implementation of ProfileManagementExportHandler. Processes the command to export profiles
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("PROFILEMANAGEMENTEXPORT command handler");

        PkiCommandResponse commandResponse = null;

        if (command.hasProperty(Constants.ALLFIELDS)) {
            additionalFeildsRequired = true;
        }

        try {
            final String profileName = command.getValueString(Constants.NAME);
            final ProfileType profileType = extractProfileType(command);

            final Profiles profiles = getBulkExportProfiles(profileType, profileName);

            commandResponse = buildCommandResponse(profiles);
        } catch (final ProfileNotFoundException profileNotFoundException) {
            logger.debug(PkiErrorCodes.PROFILE_NOT_FOUND, profileNotFoundException);
            return prepareErrorMessage(ErrorType.NO_PROFILE_FOUND_MATCHING_CRITERIA.toInt(), PkiErrorCodes.NO_PROFILE_OF_GIVEN_TYPE);
        } catch (final InvalidProfileAttributeException invalidProfileAttributeException) {
            logger.debug(invalidProfileAttributeException.getMessage(), invalidProfileAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_ATTRIBUTE_EXCEPTION.toInt(),
                    PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + invalidProfileAttributeException.getMessage());
        } catch (final InvalidProfileException InvalidProfileException) {
            logger.debug(InvalidProfileException.getMessage(), InvalidProfileException);
            return prepareErrorMessage(ErrorType.INVALID_PROFILE_EXCEPTION.toInt(), Constants.SPACE_STRING + InvalidProfileException.getMessage());

        } catch (final ProfileServiceException profileServiceException) {
            return prepareErrorMessage(ErrorType.PROFILE_SERVICE_EXCEPTION.toInt(), Constants.SPACE_STRING + PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    profileServiceException);
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + Constants.SPACE_STRING + missingMandatoryFieldException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.debug(illegalArgumentException.getMessage(), illegalArgumentException);
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + Constants.SPACE_STRING + illegalArgumentException.getMessage());
        } catch (final CommandSyntaxException commandSyntaxException) {
            logger.debug(commandSyntaxException.getMessage(), commandSyntaxException);
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), commandSyntaxException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.PROFILEMANAGEMENTEXPORT", "ProfileManagementExportHandler",
                "Bulk profiles exported successfully", "Export profiles", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while exporting the profiles {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {}  occured while exporting the profiles: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
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

    private Profiles getBulkExportProfiles(final ProfileType profileType, final String profileName) throws IllegalArgumentException, InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException {
        Profiles profiles = null;

        if (profileName == null) {
            if (additionalFeildsRequired) {
                profiles = eServiceRefProxy.getProfileManagementService().exportProfiles(profileType);
            } else {
                profiles = eServiceRefProxy.getProfileManagementService().exportProfilesForImport(profileType);
            }
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

        AbstractProfile abstractProfile = null;

        if (additionalFeildsRequired) {
            abstractProfile = eServiceRefProxy.getProfileManagementService().getProfile(profile);
        } else {
            abstractProfile = eServiceRefProxy.getProfileManagementService().getProfileForImport(profile);
        }

        final List<T> profilesList = new ArrayList<>();
        profilesList.add((T) abstractProfile);

        return commandHandlerUtils.setProfiles(abstractProfile.getType(), profilesList);
       }

    private PkiCommandResponse buildCommandResponse(final Profiles profiles) {
        if (profiles == null) {
            return PkiCommandResponse.message(Constants.NO_PROFILE_FOUND_TO_EXPORT);
        }

        return buildPkiCommandResponse(profiles);
        }

    private PkiCommandResponse buildPkiCommandResponse(final Profiles profiles) {
        final String xmlContent = JaxbUtil.getXml(profiles, true);
        final String fileIdentifier = CliUtil.generateKey();

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName("exported" + fileIdentifier + ".xml");
        downloadFileHolder.setContentType(Constants.XML_CONTENT_TYPE);
        downloadFileHolder.setContentToBeDownloaded(xmlContent.getBytes());

        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);

        logger.debug("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);

        return commandResponse;
    }
}