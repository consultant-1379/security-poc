/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
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
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;

/**
 * <p>
 * Handler implementation for TrustManagementListHandler. This provides service to List certificate(s) for CA/EE entity based on entity name.
 * </p>
 *
 * "pkiadm" ( "trustmgmt" | "tsm" ) LIST ENTITY_TYPE [ENTITY_NAME]
 *
 * LIST ::= ( "--list" | "-l" )
 *
 * ENTITY_TYPE ::= ("--entitytype"|"-type") ENT_TYPE
 *
 * ENT_TYPE ::= "CA" | "EE"
 *
 * ENTITY_NAME ::= ("--entityname"|"-en") " " <entity_name>
 *
 * @author tcsviga
 *
 */

@CommandType(PkiCommandType.TRUSTMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class TrustManagementListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    private CommandHandlerUtils commandHandlerUtils;

    @Inject
    SystemRecorder systemRecorder;

    List<TrustedEntityInfo> trustedEntityInfoList = null;
    private static final String[] publishedCertificateHeader = { "Entity Type", "Certificate Serial No.", "Subject", "Issuer", "Certificate Status", "TDPS URL(s)" };

    /**
     * Method implementation for TrustManagementListHandler. This provides service to List certificate(s) for CA/EE entity based on entity name.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.debug("TRUSTMANAGEMENTLIST command handler");

        try {
            final String entityTypeValue = command.getValueString(Constants.ENTITY_TYPE);
            final EntityType entityType = commandHandlerUtils.getEntityType(entityTypeValue);

            String entityName = command.getValueString(Constants.ENTITYNAME);
            if (entityName == null) {
                trustedEntityInfoList = eServiceRefProxy.getEntityManagementService().getTrustedEntitiesInfo(entityType);
            } else {
                entityName = entityName.replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, Constants.EMPTY_STRING);
                trustedEntityInfoList = eServiceRefProxy.getEntityManagementService().getTrustedEntitiesInfo(entityType, entityName);
            }
            systemRecorder.recordSecurityEvent("PKIWebCLI.TRUSTMANAGEMENTLIST", "TrustManagementListHandler",
                    "Certificates listed successfully for entity : " + entityName, "List published certificates",
                    ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    entityServiceException);
        } catch (final EntityNotFoundException entityNotFoundException) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST + Constants.SPACE_STRING + Constants.EMPTY_STRING);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND);
        } catch (final TrustDistributionPointURLNotFoundException trustDistributionPointURLNotFoundException) {
            return prepareErrorMessage(ErrorType.HOST_NOT_FOUND_EXCEPTION.toInt(), trustDistributionPointURLNotFoundException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + Constants.SPACE_STRING + illegalArgumentException.getMessage());

        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        return buildCommandResponse(trustedEntityInfoList);

    }

    private PkiCommandResponse buildCommandResponse(final List<TrustedEntityInfo> trustedEntityInfoList) {
        if (ValidationUtils.isNullOrEmpty(trustedEntityInfoList)) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.NO_TRUST_ENTITY_FOUND);
        }

        return buildPkiCommandResponse(trustedEntityInfoList);
    }

    private PkiCommandResponse buildPkiCommandResponse(final List<TrustedEntityInfo> trustedEntityInfoList) {
        final int numberOfColumns = publishedCertificateHeader.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation(Constants.TRUSTED_LIST_OF_CERTIFICATES);
        commandResponse.add(Constants.ENTITY_NAME, publishedCertificateHeader);

        for (final TrustedEntityInfo trustedEntityInfo : trustedEntityInfoList) {
            commandResponse.add(trustedEntityInfo.getEntityName(), getTrustedEntityInfoDetails(trustedEntityInfo));
        }

        return commandResponse;
    }

    private String[] getTrustedEntityInfoDetails(final TrustedEntityInfo trustedEntityInfo) {
        final StringBuilder tdpsUrlsbStringBuilder = new StringBuilder(300);
        tdpsUrlsbStringBuilder.append(Constants.IPv4).append(Constants.COLON_OPERATOR).append(Constants.LEFT_CURLY_BRACE).append(trustedEntityInfo.getIpv4TrustDistributionPointURL())
                .append(Constants.RIGHT_CURLY_BRACE).append(Constants.NEXT_LINE).append(Constants.IPv6).append(Constants.COLON_OPERATOR).append(Constants.LEFT_CURLY_BRACE)
                .append(trustedEntityInfo.getIpv6TrustDistributionPointURL()).append(Constants.RIGHT_CURLY_BRACE);

        final String[] trustedEntityInfoDetails = { trustedEntityInfo.getEntityType().toString(), Constants.EMPTY_STRING + trustedEntityInfo.getCertificateSerialNumber(),
                Constants.EMPTY_STRING + trustedEntityInfo.getSubjectDN(), Constants.EMPTY_STRING + trustedEntityInfo.getIssuerDN(), Constants.EMPTY_STRING + trustedEntityInfo.getCertificateStatus(),
                Constants.EMPTY_STRING + tdpsUrlsbStringBuilder };

        return trustedEntityInfoDetails;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while listing the Trust Certificates {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the Trust Certificates: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }
}
