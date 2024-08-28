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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.X500NameTokenizer;
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
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.ExtcaImportCertificateParamsValidator;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UseValidator;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;

/**
 * Handler implementation for CertificateManagementImportExtCA.
 *
 * "pkiadm" "extcaimport" ("--name" | "-n") EXT_CA_NAME --filename file:FILENAME
 *
 *
 */

@CommandType(PkiCommandType.EXTERNALCACERTIMPORT)
@UseValidator({ ExtcaImportCertificateParamsValidator.class })
@Local(CommandHandlerInterface.class)
public class CertificateManagementImportExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    CliUtil cliUtil;

    /**
     * Method implementation of ExtCACertificateManagementService. Processes the command to import External CA certificate.
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("EXTERNALCACERTIMPORT command handler");

        boolean enableRFCValidation = false;

        X509Certificate certificate = null;

        try {
            certificate = commandHandlerUtils.getCertificateFromInputFile(command);
        } catch (CertificateNotFoundException | IllegalArgumentException e) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_PARSER, e.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_PARSER, e);
            return prepareErrorMessage(ErrorType.INVALID_FILE_CONTENT.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_PARSER, PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE);
        } catch (final CertificateException ex) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE, ex.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE, ex);
            return prepareErrorMessage(ErrorType.EXTCA_CERTIFICATE_FILE_BAD_FORMAT.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE, PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE);
        }
        String caName = command.getValueString(Constants.NAME);
        enableRFCValidation = Boolean.parseBoolean(command.getValueString(Constants.RFC_VALIDATION));
        try {
        if (caName == null || caName.isEmpty()) {
            caName = getCnFromSubjectDn(certificate.getSubjectDN().getName());
        }

            final Boolean chainRequired = isChainRequired(command.getValueString(Constants.CHAIN_REQUIRED));
            if (chainRequired) {
                eServiceRefProxy.getExtCaCertificateManagementService().importCertificate(caName, certificate, enableRFCValidation);
            } else {

                eServiceRefProxy.getExtCaCertificateManagementService().forceImportCertificate(caName, certificate, enableRFCValidation);

            }

        } catch (final CertificateNotFoundException ex) {
            logger.error(PkiErrorCodes.ISSUER_CERTIFICATE_NOT_FOUND_FOR_GIVEN_EXTERNAL_CA, ex.getMessage());
            logger.debug(PkiErrorCodes.ISSUER_CERTIFICATE_NOT_FOUND_FOR_GIVEN_EXTERNAL_CA, ex);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.ISSUER_CERTIFICATE_NOT_FOUND_FOR_GIVEN_EXTERNAL_CA, PkiErrorCodes.SUGGEST_CHECK_EXTCANAME_OR_CERT_EMPTY);
        } catch (final MissingMandatoryFieldException ex) {
            logger.error(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex.getMessage());
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + ex.getMessage(),
                    PkiErrorCodes.SUGGEST_CHECK_EXTCANAME_OR_CERT_EMPTY);
        } catch (final ExternalCANotFoundException ex) {
            logger.error(PkiErrorCodes.EXTCA_NOT_FOUND, ex.getMessage());
            logger.debug(PkiErrorCodes.EXTCA_NOT_FOUND, ex);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), " " + ex.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME_OR_CERT_EMPTY);
        } catch (final ExternalCAAlreadyExistsException e1) {
            if (e1.getMessage() == null || e1.getMessage().isEmpty()) {
                return prepareErrorMessage(ErrorType.EXTCANAME_MISMATCH.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + PkiErrorCodes.EXTCANAME_IS_WRONG, PkiErrorCodes.SUGGEST_CHECK_MISMATCH_CERT_CA);
            } else if (PkiErrorCodes.CERTIFICATE_WITH_DIFFERENT_SUBJECTDN.equals(e1.getMessage())) {
                return prepareErrorMessage(ErrorType.EXTCANAME_MISMATCH.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + PkiErrorCodes.EXTCANAME_IS_WRONG, PkiErrorCodes.SUGGEST_CHECK_MISMATCH_CERT_CA);
            } else {
                return prepareErrorMessage(ErrorType.CANAME_IS_NOT_EXTERNAL.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + e1.getMessage(), PkiErrorCodes.SUGGEST_CHECK_CANAME_FOR_IMPORT_EXTCA);
            }
        } catch (final CertificateFieldException e) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, e.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, e);
            return prepareErrorMessage(ErrorType.INVALID_FILE_CONTENT.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE);
        } catch (final ExternalCredentialMgmtServiceException ex) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, ex.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, ex);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, ex);
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, illegalArgumentException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, illegalArgumentException);
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + illegalArgumentException.getMessage(), PkiErrorCodes.SUGGEST_CHIAN_REQUIRED);
        } catch (final SecurityViolationException securityViolationException) {
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION , expiredCertificateException.getMessage());
            logger.debug(PkiErrorCodes.EXPIRED_CERTIFICATE, expiredCertificateException.getMessage());
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), expiredCertificateException.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCA_CERTIFICATE);
        } catch (final CertificateAlreadyExistsException certificateAlreadyExistsException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_ALREADY_EXISTS, certificateAlreadyExistsException);
            return prepareErrorMessage(ErrorType.EXTCACERTIFICATE_ALREADY_EXISTS.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_EXISTS, Constants.EMPTY_STRING);
         } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        systemRecorder.recordEvent("PKISERVICE.EXTERNALCACERTIFICATESERVICE", EventLevel.COARSE, "PKI.EXTERNALCACERTIMPORT", "External CA imported " + caName,
                "Successfully imported External CA certificate");
        float remainingDaysForCertExpiry = (certificate.getNotAfter().getTime() - new Date().getTime())/ (float)(1000*3600*24);
        if ( remainingDaysForCertExpiry > 0 && remainingDaysForCertExpiry <= 30  ){
            return PkiCommandResponse.message(Constants.IMPORT_EXT_CERT_SUCCESSFUL_INFO, PkiErrorCodes.WARNING_CHECK_EXTCA_CERTIFICATE);
        }
        else {
            return PkiCommandResponse.message(Constants.IMPORT_EXT_CERT_SUCCESSFUL_INFO);
            }
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while generating the certificate: {}", errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while generating the certificate: {} ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));
    }

    private boolean isChainRequired(final String needChain) throws IllegalArgumentException {

        Boolean chainRequired = false;

        switch (needChain.toUpperCase()) {
        case Constants.TRUE:
            chainRequired = true;
            break;
        case Constants.FALSE:
            chainRequired = false;
            break;
        default:
            throw new IllegalArgumentException(PkiErrorCodes.UNSUPPORTED_CHAIN_REQUIRED);
        }
        return chainRequired;
    }

    private String getCnFromSubjectDn(final String subjectDN) {

        final X500Name x500Name = new X500Name(subjectDN);
        final String distinguishedName= x500Name.toString();
        final X500NameTokenizer x500Tokenizer = new X500NameTokenizer(distinguishedName, ',');
        ArrayList<String> rdnNames = new ArrayList<>();
        while (x500Tokenizer.hasMoreTokens()) {
            rdnNames.add(x500Tokenizer.nextToken());
        }
        String commonName = null;
        int indexOf;
        String rdnType = "cn=";
        for (String s : rdnNames) {
            if (s.toLowerCase(Locale.ROOT).contains(rdnType)) {
                indexOf = s.toLowerCase(Locale.ROOT).indexOf(rdnType);
                commonName = s.substring(indexOf + 3);
                break;
            }
        }
        if (commonName == null || commonName.isEmpty()){
            final String errorMessage = "Empty or Null Common Name in the the Certificate Subject/Issuer Dn :"+ distinguishedName;
            throw new MissingMandatoryFieldException(errorMessage);
        }
        return commonName.replace("\\", "").replace("\"", "");
    }

}