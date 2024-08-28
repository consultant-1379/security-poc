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

import java.util.*;

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
import com.ericsson.itpf.security.pki.web.cli.local.service.api.CertificateManagementLocalService;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;

/**
 * Handler implementation for CRLmanagementgenerate. This provides service to generate CRL.
 *
 * "pkiadm" ( "crlmgmt" | "crm" ) GENERATE CACERTIFICATE_IDENTIFIER | CA_ENTITY_NAME [ STATUS ]
 *
 * GENERATE ::= ( "--generate" | "-g" ) CACERTIFICATE_IDENTIFIER ::= CA_ENTITY_NAME CA_CERT_SERIAL_NO CA_ENTITY_NAME ::= ("--caentityname" | "-caen") <ca_entity_name1>,<ca_entity_name2>....
 * CA_CERT_SERIAL_NO ::= ("--serialno" | "-sno" ) <ca_certificate_serial_number> STATUS ::= ( "--status"|"-s" )
 *
 * @author xvambur
 *
 *
 */
@CommandType(PkiCommandType.CRLMANAGEMENTGENERATE)
@Local(CommandHandlerInterface.class)
public class CRLManagementGenerateCRLHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    private CertificateManagementLocalService certificateManagementLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;


    private PkiCommandResponse commandResponse = null;
    private boolean hasMultipleCAs = false;
    private final List<String> inactiveStatusCertCAs = new ArrayList<>();
    private final List<String> activeStatusCertCAs = new ArrayList<>();
    private final List<String> invalidStatusCertCAs = new ArrayList<>();

    /**
     * Method implementation for CRLManagementGenerateHandler.Processes the command to generate the CRL from service.
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.debug("CRLMANAGEMENTGENERATE command handler");
        CertificateStatus certificateStatus = null;
        String status = null;
        String caName = null;
        final StringBuilder successfulGeneratedItems = new StringBuilder();
        final StringBuilder unsuccessfulGeneratedItems = new StringBuilder();
        final int numberOfColumns = Constants.CRL_HEADER.length;
        final PkiNameMultipleValueCommandResponse multipleValueCommandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);
        multipleValueCommandResponse.add(Constants.ENTITY_NAME, Constants.CRL_HEADER);
        try {
            caName = command.getValueString(Constants.CA_ENTITY_NAME).replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, "");
            if (ValidationUtils.isNullOrEmpty(caName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }
            if (command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                final String serialNumber = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);
                if (ValidationUtils.isNullOrEmpty(serialNumber)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);
                }
                commandResponse = generateCRL(caName, serialNumber);
            } else {
                if (command.hasProperty(Constants.CERTIFICATE_STATUS)) {
                    status = command.getValueString(Constants.CERTIFICATE_STATUS).replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, "");

                    if (ValidationUtils.isNullOrEmpty(status)) {
                        return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NO_CANNOT_BE_NULL_OR_EMPTY);
                    }
                    final List<String> certificateStatusList = cliUtil.splitBySeprator(status, ", ");
                    if (certificateStatusList.size() > 1) {
                        return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.MULTIPLE_CERTIFICATE_STATUS_NOT_ALLOWED);
                    }
                    certificateStatus = commandHandlerUtils.getCertificateStatus(status.toLowerCase());
                }
                final List<String> caNameList = cliUtil.splitBySeprator(caName, ", ");
                if (caNameList.size() > 1) {
                    hasMultipleCAs = true;
                }
                if (certificateStatus == null) {
                    commandResponse = prepareMultipleCaResponse(caNameList, successfulGeneratedItems, unsuccessfulGeneratedItems, multipleValueCommandResponse);
                } else {
                    generateCRL(caNameList, successfulGeneratedItems, unsuccessfulGeneratedItems, multipleValueCommandResponse, certificateStatus);
                    commandResponse = prepareResponseMessage(cliUtil.removeUnwantedCommaFromString(successfulGeneratedItems), cliUtil.removeUnwantedCommaFromString(unsuccessfulGeneratedItems),
                            caNameList, multipleValueCommandResponse);
                }

            }
            systemRecorder.recordSecurityEvent("PKIWebCLI.CRLMANAGEMENTGENERATE", "CRLManagementGenerateCRLHandler",
                    "CRL generated successfully for CA entity: " + caName, "Generate CRL", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final CANotFoundException cANotFoundException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_FAILED, cANotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND.toInt(), PkiErrorCodes.CRL_GENERATION_FAILED + String.format(PkiErrorCodes.INVALID_CA_ENTITY, caName));
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_FAILED_INVALID_CERTIFICATE_STATUS, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.CRL_GENERATION_FAILED + PkiErrorCodes.INVALID_CA_AND_SERIAL_NUMBER);
        } catch (final CRLGenerationException cRLGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION, cRLGenerationException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION + cRLGenerationException.getMessage());
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CRL_GENERATION_FAILED + PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION);
        } catch (final CRLServiceException crlServiceException) {
            return prepareErrorMessage(ErrorType.REVOCATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, crlServiceException);
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION, invalidCRLGenerationInfoException);
            return prepareErrorMessage(ErrorType.INVALID_CRL_GENERATION_INFO.toInt(), PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION + invalidCRLGenerationInfoException.getMessage());
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_FAILED, revokedCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CRL_GENERATION_FAILED + PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION);
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.debug(String.format(PkiErrorCodes.CRL_GENERATION_FAILED_INVALID_CERTIFICATE_STATUS, status), illegalArgumentException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), String.format(PkiErrorCodes.CRL_GENERATION_FAILED_INVALID_CERTIFICATE_STATUS, status));
        } catch (final InvalidCertificateStatusException invalidCertificateStatusException) {
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE_STATUS_EXCEPTION.toInt(), String.format(
                    PkiErrorCodes.CRL_GENERATION_FAILED_INVALID_CERTIFICATE_STATUS, (certificateStatus != null) ? certificateStatus.toString()
                            : " "), invalidCertificateStatusException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        return commandResponse;
    }

    private PkiCommandResponse generateCRL(final String cAName, final String serialNo) throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLServiceException,
            ExpiredCertificateException, InvalidCRLGenerationInfoException, RevokedCertificateException {

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier(cAName, serialNo);

        eServiceRefProxy.getCrlManagementService().generateCRL(caCertificateIdentifier);

        return PkiCommandResponse.message(Constants.CRL_GENERATED_SUCCESSFULLY + " by " + caCertificateIdentifier.getCaName() + ".");
    }

    private void generateCRL(final List<String> caNameList, final StringBuilder successfulGeneratedItems, final StringBuilder unSuccessfulGeneratedItems,
            final PkiNameMultipleValueCommandResponse multipleValueCommandResponsefinal, final CertificateStatus... certificateStatus) throws InvalidCertificateStatusException {

        final Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationMap = eServiceRefProxy.getCrlManagementService().generateCRL(caNameList, certificateStatus);
        prepareResponseMessage(crlGenerationMap, successfulGeneratedItems, unSuccessfulGeneratedItems, multipleValueCommandResponsefinal);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while generating the CRL: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while generating the CRL: {} " , PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private void prepareResponseMessage(final Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationMap, final StringBuilder successfulGeneratedItems,
            final StringBuilder unsuccessfulGeneratedItems, final PkiNameMultipleValueCommandResponse multipleValueCommandResponsefinal) throws CRLServiceException {

        if (crlGenerationMap.size() == 0) {
            throw new CRLServiceException("Failed to get Status");
        }

        final Iterator<Map.Entry<CACertificateIdentifier, CRLGenerationStatus>> crlGenerationStatusEntries = crlGenerationMap.entrySet().iterator();
        while (crlGenerationStatusEntries.hasNext()) {
            final Map.Entry<CACertificateIdentifier, CRLGenerationStatus> crlGenerationStatusEntry = crlGenerationStatusEntries.next();

            final CRLGenerationStatus crlGenerationStatus = crlGenerationStatusEntry.getValue();

            switch (crlGenerationStatus) {
            case CRL_GENERATION_SUCCESSFUL:
                final String successfulGeneratedItem = ((!hasMultipleCAs) ? crlGenerationStatusEntry.getKey().getCerficateSerialNumber() : (crlGenerationStatusEntry.getKey().getCaName()));
                if (!successfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    successfulGeneratedItems.append(successfulGeneratedItem).append(",");
                }
                continue;

            case CERTIFICATE_NOT_FOUND:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.CERTIFICATE_NOT_FOUND_EXCEPTION).toString(),
                        PkiErrorCodes.NO_VALID_CA_ENTITY_CERTIFICATE_FOUND });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }
                continue;
            case CA_ENTITY_NOT_FOUND:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.CA_NOT_FOUND_EXCEPTION).toString(),
                                        String.format(PkiErrorCodes.INVALID_CA_ENTITY, crlGenerationStatusEntry.getKey().getCaName()) });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }

                continue;
            case CRLGENERATION_INFO_NOT_FOUND:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.CRLGENERATION_INFO_NOT_FOUND).toString(),
                        PkiErrorCodes.CRL_GENERATION_INFO_NOT_FOUND });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }
                continue;
            case CRLGENERATION_INFO_NOT_VALID:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.CRLGENERATION_INFO_NOT_FOUND).toString(),
                        "CRLGenerationInfo is not valid." });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }
                continue;
            case GENERATE_CRL_ERROR:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.INTERNAL_SERVICE_EXCEPTION).toString(),
                        "Internal Service Error while generating CRL. " + PkiErrorCodes.CONSULT_ERROR_LOGS });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }
                continue;
            case NO_VALID_CERTIFICATE_FOUND:
                multipleValueCommandResponsefinal.add(crlGenerationStatusEntry.getKey().getCaName(), new String[] { cliUtil.getErrorCode(ErrorType.INVALID_CERTIFICATE).toString(),
                        "Valid Certificates are not found" });
                if (!unsuccessfulGeneratedItems.toString().contains(crlGenerationStatusEntry.getKey().getCaName())) {
                    unsuccessfulGeneratedItems.append(crlGenerationStatusEntry.getKey().getCaName()).append(", ");
                }
                continue;
            default:
                logger.error("Invalid crl generation status {} for caName {}", crlGenerationStatus, crlGenerationStatusEntry.getKey());
            }
        }
        logger.info("Crl generation unsuccessful for {}", unsuccessfulGeneratedItems);

    }

    private PkiCommandResponse prepareResponseMessage(final String successfulList, final String unSuccessfulList, final List<String> caNameList,
            final PkiNameMultipleValueCommandResponse commandResponse) {

        String msg = "";

        if (!successfulList.isEmpty() && !unSuccessfulList.isEmpty()) {
            msg = prepareSuccessMessage(successfulList, caNameList) + "\n" + String.format(Constants.FAILURE_CRL_GENERATION, unSuccessfulList) + '.' + " Please check the details below.";
            commandResponse.setAdditionalInformation(msg);
            return commandResponse;
        }

        if (!successfulList.isEmpty()) {
            msg = prepareSuccessMessage(successfulList, caNameList);
            return PkiCommandResponse.message(msg);
        }

        if (!unSuccessfulList.isEmpty()) {
            msg = String.format(Constants.FAILURE_CRL_GENERATION, unSuccessfulList) + '.' + " Please check the details below.";
            commandResponse.setAdditionalInformation(msg);
            return commandResponse;
        }

        return commandResponse;
    }

    private String prepareSuccessMessage(final String successfulList, final List<String> caNameList) {
        String successMessage = "";
        if (caNameList.size() == 1) {
            successMessage = (String.format(Constants.SUCCESS_CRL_GENERATION_WITH_SNO, caNameList.get(0), successfulList));
        } else {
            successMessage = (String.format(Constants.SUCCESS_CRL_GENERATION_FOR_MULTIPLE_CA, successfulList));
        }
        return successMessage.substring(0, successMessage.length()) + '.';
    }

    private PkiCommandResponse prepareMultipleCaResponse(final List<String> caNameList, final StringBuilder successfulGeneratedItems, final StringBuilder unsuccessfulGeneratedItems,
            final PkiNameMultipleValueCommandResponse multipleValueCommandResponse) throws CertificateNotFoundException {

        filterCaNamesByStatus(caNameList);

        if (!activeStatusCertCAs.isEmpty()) {
            generateCRL(activeStatusCertCAs, successfulGeneratedItems, unsuccessfulGeneratedItems, multipleValueCommandResponse, CertificateStatus.ACTIVE);
        }

        if (!inactiveStatusCertCAs.isEmpty()) {
            generateCRL(inactiveStatusCertCAs, successfulGeneratedItems, unsuccessfulGeneratedItems, multipleValueCommandResponse, CertificateStatus.INACTIVE);
        }
        
        // For invalid certificate CA's by default we are passing active status as the status is mandatory and all the exceptions will be handled in manager
        if (!invalidStatusCertCAs.isEmpty()) {
            generateCRL(invalidStatusCertCAs, successfulGeneratedItems, unsuccessfulGeneratedItems, multipleValueCommandResponse, CertificateStatus.ACTIVE);
        }
        

        commandResponse = prepareResponseMessage(cliUtil.removeUnwantedCommaFromString(successfulGeneratedItems), cliUtil.removeUnwantedCommaFromString(unsuccessfulGeneratedItems), caNameList,
                multipleValueCommandResponse);
        return commandResponse;

    }

    private void filterCaNamesByStatus(final List<String> caNameList) throws CertificateNotFoundException {

        for (String cAName : caNameList) {

            try {
                List<Certificate> certList = certificateManagementLocalService.listCertificates(cAName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
                if (certList == null || certList.isEmpty()) {
                    throw new CertificateNotFoundException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
                }
                for (Certificate certificate : certList) {

                    if (certificate.getStatus().equals(CertificateStatus.ACTIVE)) {
                        activeStatusCertCAs.add(cAName);
                    }
                    if (certificate.getStatus().equals(CertificateStatus.INACTIVE) && (!inactiveStatusCertCAs.contains(cAName))) {
                            inactiveStatusCertCAs.add(cAName);
                    }

                }

            } catch (final Exception exception) {
                logger.debug("Exception while getting CAName by status", exception);
                if (!invalidStatusCertCAs.contains(cAName)) {
                    invalidStatusCertCAs.add(cAName);
                }
            }
        }
    }
}
