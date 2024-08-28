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

import java.io.File;
import java.io.IOException;
import java.util.*;

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
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * Handler implementation for Crlmanagementdownload. This provides service to download CRL entity
 *
 *
 * pkiadm ( "crlmgmt" | "crm" ) DOWNLOAD CACERTIFICATE_IDENTIFIER | CRL_IDENTIFIER |(CA_ENTITY_NAME STATUS)
 *
 * DOWNLOAD ::= ("--download"| "-dl") CACERTIFICATE_IDENTIFIER ::=CA_ENTITY_NAME CA_CERT_SERIAL_NO CA_ENTITY_NAME ::= ("--caentityname" | "-caen") <ca_entity_name> CA_CERT_SERIAL_NO ::= ("--serialno"
 * | "-sno" ) <ca_certificate_serial_number> CRL_IDENTIFIER ::=CA_ENTITY_NAME CRL_NUMBER CRL_NUMBER ::= ("–-crlnumber" | "-cn") <crl_number> STATUS ::= ( "--status"|"-s" )
 *
 * @author xvambur
 *
 */

@CommandType(PkiCommandType.CRLMANAGEMENTDOWNLOAD)
@Local(CommandHandlerInterface.class)
public class CRLMangementDownloadCRLHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    CRLUtils cRLUtils;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    private static String NO_CERTIFICATE_FOUND = null;

    /**
     * Method implementation for CRLManagementDownloadHandler.Processes the command to download the CRL from service.
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.debug("CRLMANAGEMENTDOWNLOAD command handler");

        PkiCommandResponse commandResponse = null;
        CRLInfo crlInfo = null;
        List<CRLInfo> crlInfoList = null;
        File zipfile = null;
        String status = null;
        String caName = null;
        CertificateStatus certificateStatus = null;
        try {
            caName = command.getValueString(Constants.CA_ENTITY_NAME);

            if (ValidationUtils.isNullOrEmpty(caName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            if (command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                final String serialNumber = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);

                if (ValidationUtils.isNullOrEmpty(serialNumber)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);
                }
                crlInfo = getCrl(caName, serialNumber);
                commandResponse = buildCommandResponse(crlInfo, caName);

            } else if (command.hasProperty(Constants.CRL_NUMBER)) {

                final String crlNumberValue = command.getValueString(Constants.CRL_NUMBER);

                if (ValidationUtils.isNullOrEmpty(crlNumberValue)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CRL_NUMBER_CANNOT_BE_NULL_OR_EMPTY);
                }

                crlInfo = getCrlByCRLNumber(caName, crlNumberValue);
                commandResponse = buildCommandResponse(crlInfo, caName);
            } else if (command.hasProperty(Constants.CERTIFICATE_STATUS)) {

                status = command.getValueString(Constants.CERTIFICATE_STATUS);
                if (ValidationUtils.isNullOrEmpty(status)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NO_CANNOT_BE_NULL_OR_EMPTY);
                }
                certificateStatus = commandHandlerUtils.getCertificateStatus(status.toLowerCase());

                crlInfoList = getCrl(caName, certificateStatus);
                final File[] files = cRLUtils.createCRLFiles(crlInfoList, caName);
                zipfile = cRLUtils.createZipFile(files, CliUtil.getTempFile(Constants.CRL_ZIP_FILE_NAME, Constants.ZIP_FILE_EXTENSION));

                commandResponse = buildCommandResponse(caName, zipfile);
            }
            systemRecorder.recordSecurityEvent("PKIWebCLI.CRLMANAGEMENTDOWNLOAD", "CRLMangementDownloadCRLHandler",
                    "CRL downloaded successfully for CA entity: " + caName, "Download CRL's", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final CANotFoundException cANotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, cANotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.CRL_DOWNLOAD_FAILED + String.format(PkiErrorCodes.INVALID_CA_ENTITY, caName));
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            if (command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.INVALID_SERIAL_NUMBER;
            } else {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.CERTIFICATE_WITH_STATUS_NOT_FOUND;
            }
            logger.debug("CRL download failed. " + NO_CERTIFICATE_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), "CRL download failed. " + NO_CERTIFICATE_FOUND);

        } catch (final CRLGenerationException cRLGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION, cRLGenerationException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CRL_GENERATION + cRLGenerationException.getMessage());
        } catch (final CRLNotFoundException crlNotFoundException) {
            logger.debug(PkiErrorCodes.CRL_NOT_FOUND_FOR_DOWNLOAD_CRL, crlNotFoundException);
            return prepareErrorMessage(ErrorType.CRL_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CRL_DOWNLOAD_FAILED + PkiErrorCodes.CRL_NOT_FOUND_FOR_DOWNLOAD_CRL);
        } catch (final CRLServiceException crlServiceException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, crlServiceException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION);
        } catch (CAEntityNotInternalException caEntityNotInternalException) {
            logger.debug(caEntityNotInternalException.getMessage(), caEntityNotInternalException);
            return prepareErrorMessage(ErrorType.CA_ENTITY_EXCEPTION.toInt(), caEntityNotInternalException.getMessage());
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (InvalidCertificateStatusException invalidCertificateStatusException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), String.format(PkiErrorCodes.INVALID_CERTIFICATE_STATUS_FOR_DOWNLOAD_CRL, 
                    (certificateStatus != null) ? certificateStatus.toString() : " "), invalidCertificateStatusException);
        } catch (final IOException iOException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_STORING_CRL + iOException.getMessage(), iOException);
        } catch (final IllegalArgumentException illegalArgumentException) {
            if (illegalArgumentException instanceof NumberFormatException) {
                return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + " "+illegalArgumentException.getMessage(), illegalArgumentException);
            } else {
                return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), PkiErrorCodes.INVALID_CERTIFICATE_STATUS_FOR_CRL_DOWNLOAD + status + " "+ PkiErrorCodes.CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT);
            }
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION, revokedCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        }  catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
       return commandResponse;
    }


    private CRLInfo getCrl(final String cAName, final String serialNo) throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLNotFoundException, CRLServiceException,
            ExpiredCertificateException, RevokedCertificateException {

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(cAName);
        caCertificateIdentifier.setCerficateSerialNumber(serialNo);
        return eServiceRefProxy.getCrlManagementService().getCRLByCACertificate(caCertificateIdentifier);
    }

    private CRLInfo getCrlByCRLNumber(final String cAName, final String cRLNumberValue) throws CAEntityNotInternalException, CANotFoundException, CRLNotFoundException, CRLServiceException,
            InvalidCAException, InvalidEntityAttributeException {

        final CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(Integer.parseInt(cRLNumberValue));
        return eServiceRefProxy.getCrlManagementService().getCRL(cAName, cRLNumber);
    }

    private List<CRLInfo> getCrl(final String caName, final CertificateStatus certificateStatus) throws CANotFoundException, CAEntityNotInternalException, CertificateNotFoundException,
            CRLServiceException, InvalidCertificateStatusException, InvalidEntityAttributeException {

        final List<CRLInfo> crlInfoList = new ArrayList<>();
        final Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap = eServiceRefProxy.getCrlManagementService().getCRL(caName, certificateStatus, false);
        for (final Map.Entry<CACertificateIdentifier, List<CRLInfo>> entry : crlInfoMap.entrySet()) {
            crlInfoList.addAll(entry.getValue());
        }
        return crlInfoList;
    }

    private PkiCommandResponse buildCommandResponse(final String cAName, final File file) throws IOException, CRLGenerationException {
        PkiCommandResponse pkiCommandResponse = null;

        if (file != null) {
            final byte[] cRLsBytes = cRLUtils.convertFiletoByteArray(file);
            pkiCommandResponse = cliUtil.buildPkiCommandResponse(cAName + Constants.ZIP_FILE_EXTENSION, Constants.CRL_CONTENT_TYPE, cRLsBytes);
        } else {
            throw new CRLGenerationException("NO CRL Found");
        }
        return pkiCommandResponse;
    }

    private PkiCommandResponse buildCommandResponse(final CRLInfo cRLInfo, final String cAName) throws IOException, CRLGenerationException {
        PkiCommandResponse pkiCommandResponse = null;

        if (cRLInfo != null && cRLInfo.getCrl().getX509CRLHolder() != null) {
            pkiCommandResponse = cliUtil.buildPkiCommandResponse(cAName + Constants.CRL_EXTENSION, Constants.CRL_CONTENT_TYPE, cRLInfo.getCrl().getX509CRLHolder().getCrlBytes());
        } else {
            throw new CRLGenerationException("NO CRL Found");
        }
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while downloading the CRL: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while downloading the CRL: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }
}
