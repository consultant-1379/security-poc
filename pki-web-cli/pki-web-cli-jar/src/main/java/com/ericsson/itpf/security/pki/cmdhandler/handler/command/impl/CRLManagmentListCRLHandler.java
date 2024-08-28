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

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;


/**
 *
 * Handler implementation for Crlmanagementgenerate. This provides service to list the CRL.
 *
 * "pkiadm" ( "crlmgmt" | "crm" ) LIST CA_CERTIFICATE_IDENTIFIER|(CA_ENTITY_NAME STATUS) COUNT
 *
 * LIST ::= ( "--list" | "-l" ) CA_CERTIFICATE_IDENTIFIER ::= CA_ENTITY_NAME SERIAL_NO CA_ENTITY_NAME ::= ("--caentityname" | "-caen") <ca_entity_name> CA_CERT_SERIAL_NO ::= ("--serialno" | "-sno" )
 * <ca_certificate_serial_number> STATUS ::= ( "--status"|"-s" ) COUNT ::=( "--count"|"-c" )
 *
 * @author xvambur
 *
 */
@CommandType(PkiCommandType.CRLMANAGEMENTLIST)
@Local(CommandHandlerInterface.class)
public class CRLManagmentListCRLHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

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

    final String[] cRLHeader = { "Crl Number", "Issuer Name", "Status", "This Update", "Next Update", "Is Published To Cdps" };

    PkiCommandResponse commandResponse = null;

    private static String NO_CERTIFICATE_FOUND = null;

    /**
     * Method implementation of CRLManagementListCAHandler. Handles command to list CRLs for the Entities
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.debug("CRLMANAGEMENTLIST command handler");
        String caName = null;
        List<CRLInfo> crlInfoList = null;
        int count = 0;
        CertificateStatus certificateStatus = null;
        String status = null;

        try {
            count = Integer.valueOf(command.getValueString(Constants.COUNT));
            caName = command.getValueString(Constants.CA_ENTITY_NAME);
            if (ValidationUtils.isNullOrEmpty(caName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }
            if (command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                final String serialNumber = command.getValueString(Constants.CERTIFICATE_SERIAL_NUMBER);
                if (ValidationUtils.isNullOrEmpty(serialNumber)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY);
                }

                final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
                caCertificateIdentifier.setCaName(caName);
                caCertificateIdentifier.setCerficateSerialNumber(serialNumber);
                crlInfoList = getCRL(caCertificateIdentifier);
            } else {
                status = command.getValueString(Constants.CERTIFICATE_STATUS);
                certificateStatus = commandHandlerUtils.getCertificateStatus(status.toLowerCase());
                if (ValidationUtils.isNullOrEmpty(status)) {
                    return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NO_CANNOT_BE_NULL_OR_EMPTY);
                }
                crlInfoList = getCRL(caName, certificateStatus);
            }

        } catch (final CANotFoundException caNotFoundException) {
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), "CRL listing failed. The CA entity with name " + caName + " is not found ");
        } catch (final CAEntityNotInternalException caEntityNotInternalException) {
            logger.debug(caEntityNotInternalException.getMessage(), caEntityNotInternalException);
            return prepareErrorMessage(ErrorType.CA_ENTITY_EXCEPTION.toInt(), caEntityNotInternalException.getMessage());
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            if (command.hasProperty(Constants.CERTIFICATE_SERIAL_NUMBER)) {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.INVALID_SERIAL_NUMBER;
            } else {
                NO_CERTIFICATE_FOUND = PkiErrorCodes.CERTIFICATE_WITH_STATUS_NOT_FOUND;
            }
            logger.debug(PkiErrorCodes.CRL_NOT_FOUND_FOR_LISTING_CRL, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), "CRL listing failed. " + NO_CERTIFICATE_FOUND);
        } catch (final CRLNotFoundException crlNotFoundException) {
            logger.debug(PkiErrorCodes.CRL_NOT_FOUND_FOR_LISTING_CRL, crlNotFoundException);
            return prepareErrorMessage(ErrorType.CRL_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CRL_NOT_FOUND_FOR_LISTING_CRL + caName);
        } catch (final CRLServiceException crlServiceException) {
            return prepareErrorMessage(ErrorType.REVOCATION_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, crlServiceException);
        } catch (final InvalidCertificateStatusException invalidCertificateStatusException) {

            if (CertificateStatus.EXPIRED.equals(certificateStatus)) {
                return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), String.format(PkiErrorCodes.INVALID_CERTIFICATE_STATUS_FOR_LIST_CRL, certificateStatus.toString()),
                        invalidCertificateStatusException);
            } else {
                return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), String.format(PkiErrorCodes.INVALID_CERTIFICATE_STATUS_FOR_LIST_CRL, 
                        (certificateStatus != null) ? certificateStatus.toString() : " "), invalidCertificateStatusException);
            }
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final InvalidCRLGenerationInfoException invalidCRLGenerationInfoException) {
            logger.debug(PkiErrorCodes.CRL_GENERATION_FAILED, invalidCRLGenerationInfoException);
            return prepareErrorMessage(ErrorType.INVALID_CRL_GENERATION_INFO.toInt(), PkiErrorCodes.CRL_GENERATION_FAILED + invalidCRLGenerationInfoException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            if (illegalArgumentException instanceof NumberFormatException) {
                return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_COMMAND_ARGUMENT + PkiErrorCodes.CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT);
            } else {
                return prepareErrorMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), String.format(PkiErrorCodes.INVALID_CERTIFICATE_STATUS_FOR_LIST_CRL, status)
                        + PkiErrorCodes.CERTIFICATE_STATUS_SUPPORTED_FOR_CRL_MANAGEMENT);
            }
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION);
            logger.debug(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, revokedCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_REVOKED_EXCEPTION.toInt(), "CRL listing failed. " + PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION + " .");
        } catch (final Exception exception) {
            logger.info("" + exception.getCause() + exception.getClass());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING
                    + exception.getMessage());
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CRLMANAGEMENTLIST", "CRLManagmentListCRLHandler",
                "CRL's list fetched successfully for CA entity: " + caName, "List CRL's", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return buildCommandResponse(crlInfoList, count);
    }


    private List<CRLInfo> getCRL(final String caEntityName, final CertificateStatus certificateStatus) throws CANotFoundException, CAEntityNotInternalException, CertificateNotFoundException,
            CRLServiceException, InvalidCertificateStatusException, InvalidEntityAttributeException {
        final List<CRLInfo> crlInfoList = new ArrayList<>();
        final Map<CACertificateIdentifier, List<CRLInfo>> crlInfoMap = eServiceRefProxy.getCrlManagementService().getCRL(caEntityName, certificateStatus, false);
        for (final Map.Entry<CACertificateIdentifier, List<CRLInfo>> entry : crlInfoMap.entrySet()) {
            crlInfoList.addAll(entry.getValue());
        }
        return crlInfoList;
    }


    private List<CRLInfo> getCRL(final CACertificateIdentifier cACertificateIdentifier) throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException, CRLGenerationException,
            CRLNotFoundException, CRLServiceException, InvalidCAException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException {

        return eServiceRefProxy.getCrlManagementService().getAllCRLs(cACertificateIdentifier);
    }

    private PkiCommandResponse buildCommandResponse(final List<CRLInfo> crlInfoList, final int count) {

        if (crlInfoList == null || crlInfoList.isEmpty()) {
            return prepareErrorMessage(ErrorType.CRL_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CRL_NOT_FOUND_FOR_LISTING_CRL);
        }
        final List<CRLInfo> crlInfoCountList = getCrlListWithCount(crlInfoList, count);

        return buildPkiCommandResponse(crlInfoCountList);
    }

    private PkiCommandResponse buildPkiCommandResponse(final List<CRLInfo> cRLInfoList) {

        final int numberOfColumns = cRLHeader.length;
        final PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(numberOfColumns);

        commandResponse.setAdditionalInformation(Constants.LIST_OF_CRLS);
        commandResponse.add(Constants.ID, cRLHeader);
        for (final CRLInfo cRLInfo : cRLInfoList) {
            commandResponse.add(String.valueOf(cRLInfo.getId()), getCRLDetails(cRLInfo));
        }

        return commandResponse;
    }

    private String[] getCRLDetails(final CRLInfo cRLInfo) {

        final String[] crlDetails = { cRLInfo.getCrlNumber().getSerialNumber().toString(), Constants.EMPTY_STRING + cRLInfo.getIssuerCertificate().getX509Certificate().getSubjectDN().getName(),
                Constants.EMPTY_STRING + cRLInfo.getStatus(), Constants.EMPTY_STRING + cRLInfo.getThisUpdate(), Constants.EMPTY_STRING + cRLInfo.getNextUpdate(),
                Constants.EMPTY_STRING + cRLInfo.isPublishedToCDPS() };

        return crlDetails;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while listing the cRLs: {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the cRLs: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private List<CRLInfo> getCrlListWithCount(final List<CRLInfo> crlInfoList, int count) {
        final List<CRLInfo> crlInfoCountList = new ArrayList<>();
        if (crlInfoList.size() < count) {
            count = crlInfoList.size();
        }
        crlInfoCountList.addAll(crlInfoList.subList(0, count));
        return crlInfoCountList;
    }

}
