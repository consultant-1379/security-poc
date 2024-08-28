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
 *----------------------------------------------------------------------------
 */
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import java.util.Calendar;

import javax.ejb.Local;
import javax.inject.Inject;

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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * Handler implementation for CertificateManagemtUpdateCAHandler. This provides service to renew, modify and re-key certificate(s) for CA entity based on the type the user provides.
 *
 * "pkiadm"( "certmgmt"| "ctm") "CACert" REISSUE ENTITY_NAME REISSUE_TYPE LEVEL [REVOKE] REISSUE ::("--reissue" |"-ri") ENTITY_NAME ::= ( "--entityname"| "-en") " " <entity_name> REISSUE_TYPE ::= (
 * "–reissuetype "|" -rt") (RENEW | REKEY) RENEW ::= ( "--renew"| "-rn") REKEY ::= ( "--rekey" | "-rk") LEVEL ::= ( "–level"|"-le") ( "CA"| "CA_IMMEDIATE_SUB_CAS"| "CA_ALL_CHILD_CAS") REVOKE :: =
 * ("--revoke" | "-r")
 *
 * @author xpranma
 *
 */

@CommandType(PkiCommandType.CACERTIFICATEMANAGEMENTREISSUE)
@Local(CommandHandlerInterface.class)
public class CertificateManagemtUpdateCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of CertificateManagementUpdateCAHandler, Handles command to update certificate for CA Entity based on the update type and reissue Type
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.debug("CACERTIFICATEMANAGEMENTRENEW command handler");

        String commandResponse = Constants.EMPTY_STRING;

        try {

            final String entityName = command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME);
            final String reissueType = command.getValueString(Constants.REISSUE_TYPE);
            final String level = command.getValueString(Constants.LEVEL);
            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return cliUtil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY, null);
            }

            if (reissueType.equalsIgnoreCase(Constants.RENEW_OPTION)) {

                if (command.hasProperty(Constants.REVOKE_OPTION)) {
                    commandResponse = renewAndRevokeCACertificates(entityName, level);

                } else {
                    commandResponse = renewCACertificates(entityName, level);
                }
            } else if (reissueType.equalsIgnoreCase(Constants.REKEY_OPTION)) {

                if (command.hasProperty(Constants.REVOKE_OPTION)) {

                    commandResponse = reKeyAndRevokeCACertificates(entityName, level);
                } else {
                    commandResponse = rekeyCACertificates(entityName, level);
                }
            }

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CANotFoundException caNotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final CertificateGenerationException certificateGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException);
            return prepareErrorMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION + Constants.SPACE_STRING
                    + certificateGenerationException.getMessage());
        } catch (final CertificateNotFoundException e) {
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, e);
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, e);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + PkiErrorCodes.NO_CERTIFICATE_FOUND + PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE_SN);
        } catch (final CertificateServiceException certificateServiceException) {
            logger.debug(PkiErrorCodes.SERVICE_ERROR, certificateServiceException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final IssuerCertificateRevokedException issuerCertificateRevokedException) {
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA, issuerCertificateRevokedException);
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final RevokedCertificateException revokedCertificateException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION, revokedCertificateException);
        } catch (final RevocationServiceException revocationServiceException) {
            return prepareErrorMessage(ErrorType.REVOCATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, revocationServiceException);
        } catch (final RootCertificateRevocationException rootCertificateRevocationException) {
            return prepareErrorMessage(ErrorType.ROOT_CA_CANNOT_REVOKED_CERTIFICATE.toInt(),Constants.EMPTY_STRING, rootCertificateRevocationException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION + expiredCertificateException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);

        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CACERTIFICATEMANAGEMENTRENEW", "CertificateManagemtUpdateCAHandler",
                "Certificates updated successfully for CA entity: " + command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME),
                "Update certificate for CA Entity based on the update type and reissue Type", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return PkiCommandResponse.message(commandResponse);
    }

    private String renewCACertificates(final String entityName, final String level) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);

        eServiceRefProxy.getCaCertificateManagementService().renewCertificate(entityNameFilter, getReIssueType(level));

        return String.format(Constants.RENEW_SUCCESSFUL_MESSAGE, entityName);
    }

    private String rekeyCACertificates(final String entityName, final String level) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);

        eServiceRefProxy.getCaCertificateManagementService().rekeyCertificate(entityNameFilter, getReIssueType(level));

        return String.format(Constants.REKEY_SUCCESSFUL_MESSAGE, entityName);
    }

    private String renewAndRevokeCACertificates(final String entityName, final String level) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);
        final CAReIssueInfo cAReIssueInfo = generateCAReIssueInfo(entityNameFilter, RevocationReason.UNSPECIFIED);

        eServiceRefProxy.getCaCertificateManagementService().renewCertificate(cAReIssueInfo, getReIssueType(level));

        return String.format(Constants.RENEW_AND_REVOKE_SUCCESSFUL_MESSAGE, entityName);
    }

    private String reKeyAndRevokeCACertificates(final String entityName, final String level) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);
        final CAReIssueInfo cAReIssueInfo = generateCAReIssueInfo(entityNameFilter, RevocationReason.KEY_COMPROMISE);

        eServiceRefProxy.getCaCertificateManagementService().rekeyCertificate(cAReIssueInfo, getReIssueType(level));

        return String.format(Constants.REKEY_AND_REVOKE_SUCCESSFUL_MESSAGE, entityName);
    }

    private ReIssueType getReIssueType(final String reIssueType) {

        ReIssueType reIssue = null;

        switch (reIssueType) {
        case Constants.CA_REISSUE:
            reIssue = ReIssueType.CA;
            break;

        case Constants.CA_IMMEDIATE_SUB_CAS:
            reIssue = ReIssueType.CA_WITH_IMMEDIATE_SUB_CAS;
            break;

        case Constants.CA_ALL_CHILD_CAS:
            reIssue = ReIssueType.CA_WITH_ALL_CHILD_CAS;
            break;

        }
        return reIssue;
    }

    private CAReIssueInfo generateCAReIssueInfo(final String entityNameFilter, final RevocationReason revocationReason) {

        final CAReIssueInfo cAReIssueInfo = new CAReIssueInfo();

        cAReIssueInfo.setName(entityNameFilter);
        cAReIssueInfo.setRevocationReason(revocationReason);
        cAReIssueInfo.setInvalidityDate(Calendar.getInstance().getTime());
        return cAReIssueInfo;

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured when reissuing the CA certificate {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured when reissuing the CA certificate: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }

}
