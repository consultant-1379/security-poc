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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;

/**
 *
 * Handler implementation for CertificateManagementList. This provides service to list the Certificates issued by the CA .
 *
 * "pkiadm"( "certmgmt"| "ctm" ) LIST CACERTIFICATE_IDENTIFIER[STATUS] LIST ::= ("--list" | "-l") CACERTIFICATE_IDENTIFIER ::= CA_ENTITY_NAME " " CA_CERT_SERIAL_NO CA_NAME::=("--caentityname"|
 * "-caen") " " <ca_entity_name> CA_CERT_SERIAL_NO::=("--serialno" | "-sno" ) " " <certificate_serial_number> STATUS::=("--status" | "-s")
 *
 * @author xsaufar
 *
 */

@CommandType(PkiCommandType.CERTIFICATEMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class CertificateManagementListHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

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

    final String[] certificateHeader = { "Entity Type", "Serial Number", "Subject", "SAN", "Valid From", "Valid Till", "Certificate Status" };

    PkiCommandResponse commandResponse = null;

    /**
     * Method implementation of CertificateManagementListHandler. Handles command to list certificate(s) issued by CAEntity.
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.debug("CERTIFICATEMANAGEMENTLIST command handler");

        List<CertificateInfo> certificateInfoList = null;
        final String caEntityName = command.getValueString(Constants.CA_ENTITY_NAME);

        try {

            final String serialNo = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);

            if (ValidationUtils.isNullOrEmpty(caEntityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);

            }
            if (ValidationUtils.isNullOrEmpty(serialNo)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);

            }

            final CertificateStatus[] certificateStatus = getCertificateStatus(command);

            certificateInfoList = getIssuedCertificates(caEntityName, serialNo, certificateStatus);

        } catch (final CANotFoundException caNotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_LISTING_FAILED + PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND);
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), Constants.EMPTY_STRING, illegalArgumentException);
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + Constants.SPACE_STRING + missingMandatoryFieldException.getMessage());
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CERTIFICATEMANAGEMENTLIST", "CertificateManagementListHandler",
                "Successfully listed Certificate(s) issued by CA entity: " + caEntityName, "List certificate(s) issued by CA",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return buildCommandResponse(certificateInfoList);
    }

    private CertificateStatus[] getCertificateStatus(final PkiPropertyCommand command) throws IllegalArgumentException {

        final CertificateStatus[] certificateStatus = { CertificateStatus.ACTIVE };

        if (!command.hasProperty(Constants.CERTIFICATE_STATUS)) {

            return certificateStatus;
        }
        final List<CertificateStatus> certificateStatusList = new ArrayList<>();

        final String statusValue = command.getValueString(Constants.CERTIFICATE_STATUS);

        final List<String> statusValueList = cliUtil.splitBySeparator(cliUtil.removeFirstAndLastChar(statusValue), ",");

        for (final String certificateStatusValue : statusValueList) {

            final CertificateStatus certStatus = commandHandlerUtils.getCertificateStatus(certificateStatusValue.trim());

            certificateStatusList.add(certStatus);
        }

        return certificateStatusList.toArray(new CertificateStatus[statusValueList.size()]);

    }

    private List<CertificateInfo> getIssuedCertificates(final String caEntityName, final String serialNo, final CertificateStatus[] certificateStatus) throws CANotFoundException,
            CertificateNotFoundException, CertificateServiceException, MissingMandatoryFieldException {

        List<CertificateInfo> certificateInfoList = null;
        final CACertificateIdentifier cACertificateIdentifier = new CACertificateIdentifier(caEntityName, serialNo);
        certificateInfoList = eServiceRefProxy.getCaCertificateManagementService().listIssuedCertificates(cACertificateIdentifier, certificateStatus);

        return certificateInfoList;
    }

    private PkiCommandResponse buildCommandResponse(final List<CertificateInfo> certificateInfoList) {

        if (certificateInfoList == null || certificateInfoList.isEmpty()) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_ENTITY_IS_ISSUED_BY_GIVEN_CA_AND_SERIAL_NUMBER);
        }

        return buildPkiCommandResponse(certificateInfoList);
    }

    private PkiCommandResponse buildPkiCommandResponse(final List<CertificateInfo> certificateInfoList) {

        final int numberOfColumns = certificateHeader.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation(Constants.LIST_OF_CERTIFICATES);
        commandResponse.add(Constants.ENTITY_NAME, certificateHeader);

        for (final CertificateInfo certificate : certificateInfoList) {
            commandResponse.add(certificate.getEntityName(), getCertificateDetails(certificate));
        }

        return commandResponse;
    }

    private String[] getCertificateDetails(final CertificateInfo certificateInfo) {

    	final DateFormat dateFormat = new SimpleDateFormat(Constants.DATE_FORMAT);
        final String[] certificateDetails = { Constants.EMPTY_STRING + (certificateInfo.isCAEntity() ? Constants.CA_ENTITY : Constants.END_ENTITY),
                Constants.EMPTY_STRING + certificateInfo.getSerialNumber(), Constants.EMPTY_STRING + certificateInfo.getSubject().toASN1String(), Constants.EMPTY_STRING + certificateInfo.getSubjectAltName(),
                Constants.EMPTY_STRING + dateFormat.format(certificateInfo.getNotBefore()), Constants.EMPTY_STRING + dateFormat.format(certificateInfo.getNotAfter()), Constants.EMPTY_STRING + certificateInfo.getStatus() };

        return certificateDetails;

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error:{} occured while listing the certificates {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error:{} occured while listing the certificates: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));

    }
}
