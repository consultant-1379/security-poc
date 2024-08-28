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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * Handler implementation for CertificateManagementListCA. This provides service to List certificate(s) for CA entity based on status
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "CACert" LIST CA_ENTITY_NAME [STATUS] LIST ::= ("--list" | "-l") CA_ENTITY_NAME ::= ("--entityname" | "-en") " " <entity_name> { "," <entity_name>} STATUS ::=
 * ("--status"|"-s") " " CERT_STATUS
 *
 * @author xpranma
 *
 */

@CommandType(PkiCommandType.CACERTIFICATEMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class CertificateManagementListCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    final String[] certificateHeader = { "Subject", "Status", "Issuer", "Serial Number", "valid From", "valid to" };

    PkiCommandResponse commandResponse = null;

    /**
     * Method implementation of CertificateManagementListCAHandler. Handles command to list certificate(s) for CAEntity
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CACERTIFICATEMANAGEMENTLIST command handler");

        String entityName = null;
        List<Certificate> certificates = null;

        try {

            entityName = command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME);

            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);

            }

            final CertificateStatus certificateStatus = getCertificateStatus(command);
            certificates = getCACertificates(entityName.trim(), certificateStatus);

        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND);
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED, illegalArgumentException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CACERTIFICATEMANAGEMENTLIST", "CertificateManagementListCAHandler",
                "Certificate(s) listed successfully for CA Entity : " + entityName.trim() + " with status " + getCertificateStatus(command),
                "List certificate(s) for CA entity based on status", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return buildCommandResponse(entityName.trim(), certificates);
    }

    private CertificateStatus getCertificateStatus(final PkiPropertyCommand command) throws IllegalArgumentException {

        CertificateStatus certificateStatus = null;

        if (!command.hasProperty(Constants.CERTIFICATE_STATUS)) {
            return certificateStatus;
        }

        switch (command.getValueString(Constants.CERTIFICATE_STATUS)) {
            case Constants.CERTIFICATE_ACTIVE_STATUS:
                certificateStatus = CertificateStatus.ACTIVE;
                break;

            case Constants.CERTIFICATE_REVOKED_STATUS:
                certificateStatus = CertificateStatus.REVOKED;
                break;

            case Constants.CERTIFICATE_EXPIRED_STATUS:
                certificateStatus = CertificateStatus.EXPIRED;
                break;

            case Constants.CERTIFICATE_INACTIVE_STATUS:
                certificateStatus = CertificateStatus.INACTIVE;
                break;
            default:
                throw new IllegalArgumentException(PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED);

        }

        return certificateStatus;
    }


    private List<Certificate> getCACertificates(final String entityName, final CertificateStatus certificateStatus) throws CertificateNotFoundException, CertificateServiceException,
            EntityNotFoundException, InvalidEntityAttributeException {

        List<Certificate> certificates = null;

        if (certificateStatus != null) {
            certificates = eServiceRefProxy.getCaCertificateManagementService().listCertificates_v1(entityName, certificateStatus);
        } else {
            certificates = eServiceRefProxy.getCaCertificateManagementService().listCertificates_v1(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED);
        }
        if (certificates == null || certificates.isEmpty()) {
            throw new CertificateNotFoundException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
        }
        return certificates;
    }

    private PkiCommandResponse buildCommandResponse(final String entityName, final List<Certificate> certificates) {

        if (entityName == null) {
            return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
        }

        if (certificates == null || certificates.isEmpty()) {
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.NO_ENTITY_FOUND);

        }

        return buildPkiCommandResponse(entityName, certificates);
    }

    private PkiCommandResponse buildPkiCommandResponse(final String entityName, final List<Certificate> certificates) {

        final int numberOfColumns = certificateHeader.length;
        final PkiNameMultipleValueCommandResponse multipleValueCommandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        multipleValueCommandResponse.setAdditionalInformation(Constants.LIST_OF_CERTIFICATES);
        multipleValueCommandResponse.add(Constants.ENTITY_NAME, certificateHeader);

        for (final Certificate certificate : certificates) {
            multipleValueCommandResponse.add(entityName, getCertificateDetails(certificate));
        }

        return multipleValueCommandResponse;
    }

    private String[] getCertificateDetails(final Certificate certificate) {

        final DateFormat dateFormat = new SimpleDateFormat(Constants.DATE_FORMAT);

        final String certificatesSubjectDn = new X500Name(certificate.getX509Certificate().getSubjectX500Principal().getName()).toString();
        final String certificateIssuerDn = new X500Name(certificate.getX509Certificate().getIssuerX500Principal().getName()).toString();

        final String[] certificateDetails = { certificatesSubjectDn, Constants.EMPTY_STRING + certificate.getStatus(), Constants.EMPTY_STRING + certificateIssuerDn,
                Constants.EMPTY_STRING + certificate.getSerialNumber(), Constants.EMPTY_STRING + dateFormat.format(certificate.getNotBefore()),
                Constants.EMPTY_STRING + dateFormat.format(certificate.getNotAfter()) };

        return certificateDetails;

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while listing the certificates {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage,cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the certificates: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

}
