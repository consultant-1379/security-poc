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

import java.util.Date;

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
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.util.exception.IllegalAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

/**
 * Handler implementation for RevocationManagementRevokeCert. This provides service to revoke certificate for CA Entity
 *
 * "pkiadm" ( "revmgmt" | "rem" ) "CA" REVOKE ENTITY_IDENTIFICATION [REVOCATION_REASON] [INVALIDITY_DATE] REVOKE ::= ( "--revoke" | "-rev" ) ENTITY_IDENTIFICATION ::= NAME | CERTIFICATE IDENTIFIER |
 * SUBJECTIDENTIFIER NAME ::= ENTITY_NAME ENTITY_NAME ::= ("--entityname"|"-en") " " <entity_name> CERTIFICATE_IDENTIFIER ::= ISSUER " " SERIAL_NO ISSUER ::= ("--issuer" | "-isr") " "
 * <issuer_name> SERIAL_NO ::= ("--serialNo" | "-sno" ) " " <certificate_serial_number> SUBJECTIDENTIFIER ::= SUBJECT_DN " " ISSUER_DN " " SERIAL_NO SUBJECT_DN ::= ("--subjectDN" | "-subDN") " "
 * <subject_DN_name> ISSUER_DN ::= ("--issuerDN" | "-issDN") SERIAL_NO ::= ("--serialNo" | "-sno" ) " " <certificate_serial_number> REVOCATION_REASON ::= REASON_CODE | REASON_TEXT REASON_CODE ::=
 * ("--reasoncode"|"-rc") " " REASON_CODE_VALUE REASON_CODE_VALUE ::= ( "0" | "1" | "2" | "3" | "4" | "5" | "6" | "8" | "9" | "10" ) REASON_TEXT ::= ( "--reasonText"|"-rt" ) " " REASON_TEXT_VALUE
 * REASON_TEXT_VALUE ::= ("unspecified" | "keyCompromise" | "cACompromise" | "affiliationChanged" | "superseded" | "cessationOfOperation" | "certificateHold" | "removeFromCRL" | "privilegeWithdrawn" |
 * "aACompromise" ) INVALIDITY_DATE ::=("--invalidityDate" | "-ind") " "<YYYY-MM-DD HH:mm:ss > Note:[ ] indicate optional parameter (non manadatory)
 *
 * @author xsaufar
 *
 */

@CommandType(PkiCommandType.REVOCATIONMANAGEMENTREVOKECACERT)
@Local(CommandHandlerInterface.class)
public class RevocatioManagementRevokeCACertHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

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

    private static String NO_CERTIFICATE_FOUND = null;

    /**
     *  Method implementation for RevocationManagementRevokeCertHandler.Processes the command to revoke the certificate from service.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("REVOCATIONMANAGEMENTREVOKECACERT command handler");
        String message = Constants.EMPTY_STRING;

        RevocationReason revocationReason = null;

        try {

            if (command.hasProperty(Constants.REVOCATION_REASON_TEXT) || command.hasProperty(Constants.REVOCATION_REASON_CODE)) {
                revocationReason = commandHandlerUtils.getRevocationReason(command);
            }
            final Date invalidityDate = getInvalidityDate(command);

            if (command.hasProperty(Constants.ENTITYNAME)) {

                final String entityName = command.getValueString(Constants.ENTITYNAME);

                if (ValidationUtils.isNullOrEmpty(entityName)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
                }

                message = revokeCertificate(entityName, revocationReason, invalidityDate);
                if (revocationReason != null) {
                    systemRecorder.recordSecurityEvent("PKIWebCLI.REVOCATIONMANAGEMENTREVOKECACERT", "RevocatioManagementRevokeCACertHandler",
                            "CA Certificate revoked successfully for entity: " + entityName + " due to reason: " + revocationReason.toString(),
                            "Revoke CA certificate", ErrorSeverity.INFORMATIONAL, "SUCCESS");
                }

            }

            else if (command.hasProperty(Constants.ISSUER_NAME) && command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                final String issuerName = command.getValueString(Constants.ISSUER_NAME);

                final String serialNumber = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);

                if (ValidationUtils.isNullOrEmpty(issuerName)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ISSUER_NAME_CANNOT_BE_NULL_OR_EMPTY);
                }

                if (ValidationUtils.isNullOrEmpty(serialNumber)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);
                }

                message = revokeCertificate(issuerName, serialNumber, revocationReason, invalidityDate);
                systemRecorder.recordSecurityEvent("PKIWebCLI.REVOCATIONMANAGEMENTREVOKECACERT", "RevocatioManagementRevokeCACertHandler",
                        "CA Certificate revoked successfully for issuer: " + issuerName + " and serial number: " + serialNumber, "Revoke CA certificate",
                        ErrorSeverity.INFORMATIONAL, "SUCCESS");

            } else {
                final String subjectDN = command.getValueString(Constants.SUBJECTDN).replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, Constants.EMPTY_STRING).trim();
                final String issuerDN = command.getValueString(Constants.ISSUERDN).replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, Constants.EMPTY_STRING).trim();
                final String serialNo = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);

                if (ValidationUtils.isNullOrEmpty(subjectDN)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.SUBJECT_DN_CANNOT_BE_NULL_OR_EMPTY);
                }

                if (ValidationUtils.isNullOrEmpty(serialNo)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);
                }

                if (ValidationUtils.isNullOrEmpty(issuerDN)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ISSUER_DN_CANNOT_BE_NULL_OR_EMPTY);
                }

                message = revokeCertificate(subjectDN, issuerDN, serialNo, revocationReason, invalidityDate);
                systemRecorder.recordSecurityEvent("PKIWebCLI.REVOCATIONMANAGEMENTREVOKECACERT", "RevocatioManagementRevokeCACertHandler",
                        "CA Certificate revoked successfully for subjectDN " + subjectDN + " ,issuerDN: " + issuerDN + " and serial number: " + serialNo,
                        "Revoke CA certificate", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            if (command.hasProperty(Constants.ENTITYNAME)) {
                NO_CERTIFICATE_FOUND = certificateNotFoundException.getMessage();
            } else if (command.hasProperty(Constants.ISSUER_NAME) && command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.CERTIFICATE_NOT_FOUND_WITH_CERTIFICATE_IDENTIFIER;
            } else {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.CERTIFICATE_NOT_FOUND_WITH_DNBASED_IDENTIFIER;
            }
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND_EXCEPTION.toInt(), NO_CERTIFICATE_FOUND);
        } catch (final CommonRuntimeException commonRuntimeException) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + commonRuntimeException.getMessage());
        } catch (final EntityNotFoundException entityNotFoundException) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.INVALID_ENTITY_FOR_REVOCATION);
        } catch (final EntityAlreadyExistsException entityAlreadyExistsException) {
            return prepareErrorMessage(ErrorType.ENTITY_ALREADY_EXIST_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_ALREADY_EXISTS);
        } catch (ExpiredCertificateException expiredCertificateException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), expiredCertificateException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.REVOCATION_REASON_NOT_SUPPORTED.toInt(), PkiErrorCodes.REVOCATION_REASON_NOT_SUPPORTED);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
        }  catch (IllegalAttributeException illegalAttributeException) {
            return prepareErrorMessage(ErrorType.INVALID_DATE_FORMAT_EXCEPTION.toInt(), PkiErrorCodes.INVALID_DATE_FORMAT);
        } catch (final IssuerCertificateRevokedException issuerCertificateRevokedException) {
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA);
        } catch (final IssuerNotFoundException issuerNotFoundException) {
            return prepareErrorMessage(ErrorType.ISSUER_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ISSUER_NOT_FOUND_EXCEPTION);
        } catch (final RevokedCertificateException revokedCertificateException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), revokedCertificateException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (RevocationServiceException revocationServiceException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, revocationServiceException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, revocationServiceException);
        } catch (RootCertificateRevocationException rootCertificateRevocationException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, rootCertificateRevocationException);
            return prepareErrorMessage(ErrorType.ROOT_CA_CANNOT_REVOKED_CERTIFICATE.toInt(), PkiErrorCodes.ROOT_CA_CANNOT_REVOKED_CERTIFICATE);
        } catch (final InvalidInvalidityDateException invalidInvalidityDateException) {
            logger.debug(invalidInvalidityDateException.getMessage(), invalidInvalidityDateException);
            return prepareErrorMessage(ErrorType.INVALID_DATE.toInt(), invalidInvalidityDateException.getMessage());
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING, exception);
        }
        return PkiCommandResponse.message(message);

    }


    private String revokeCertificate(final String entityName, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException, EntityAlreadyExistsException,
            EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException,
            RevocationServiceException, RootCertificateRevocationException {
        String returnMsg = Constants.EMPTY_STRING;

        eServiceRefProxy.getRevocationService().revokeCAEntityCertificates(entityName, revocationReason, invalidityDate);

        returnMsg += "Certificate with name:: " + entityName + Constants.REVOKED_SUCCESSFULLY;
        return returnMsg;
    }

    private String revokeCertificate(final String issuerName, final String serialNumber, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException,
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerNotFoundException,
            RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {
        String returnMsg = Constants.EMPTY_STRING;

        final CertificateIdentifier certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName(issuerName);
        certificateIdentifier.setSerialNumber(serialNumber);

        eServiceRefProxy.getRevocationService().revokeCertificateByIssuerName(certificateIdentifier, revocationReason, invalidityDate);

        returnMsg += "Certificate with serial number:: " + serialNumber + Constants.REVOKED_SUCCESSFULLY;

        return returnMsg;
    }

    private String revokeCertificate(final String subjectDN, final String issuerDN, final String serialNumber, final RevocationReason revocationReason, final Date invalidityDate)
            throws CertificateNotFoundException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException,
            IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {
        String returnMsg = Constants.EMPTY_STRING;
        final DNBasedCertificateIdentifier dNBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dNBasedCertificateIdentifier.setSubjectDN(subjectDN);
        dNBasedCertificateIdentifier.setIssuerDN(issuerDN);
        dNBasedCertificateIdentifier.setCerficateSerialNumber(serialNumber);

        eServiceRefProxy.getRevocationService().revokeCertificateByDN(dNBasedCertificateIdentifier, revocationReason, invalidityDate);

        returnMsg += "Certificate with subjectDN:: " + subjectDN + Constants.REVOKED_SUCCESSFULLY;

        return returnMsg;
    }

    private Date getInvalidityDate(final PkiPropertyCommand command) {
        Date invalidityDate = null;

        if (!command.hasProperty(Constants.INVALIDITY_DATE)) {
            return invalidityDate;
        }
        final String invalidityDateValue = command.getValueString(Constants.INVALIDITY_DATE);

        if (ValidationUtils.isNullOrEmpty(invalidityDateValue) || !invalidityDateValue.matches(Constants.INVALIDITY_DATE_REGEX)) {
            throw new IllegalAttributeException(PkiErrorCodes.INVALID_DATE_FORMAT);
        } else {
            invalidityDate = commandHandlerUtils.getInvalidityDateInGmt(invalidityDateValue);

        }
        return invalidityDate;

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while revoking the Certificate {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while revoking the Certificate: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
      }
}
