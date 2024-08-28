/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
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
import java.security.cert.CertificateException;
import java.util.*;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.CSRUtil;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CRLUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.exception.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw.SecGWCertificates;

/**
 * CommandHandler implementation for SecGWcertManagement. Generates certificate for SecurityGateway with provided Certificate Request in the
 * Command and downloads zip file with certificate, certificate chain and trusted certificates.
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "SecGW" GENERATE CERT_TYPE FILE_NAME [ NO_CERTIFICATE_CHAIN ] GENERATE ::= ( "--generate" | "-gen" ) CERT_TYPE
 * ::= ( "--certtype" | "-ct") " " <cert_type> FILE_NAME::= ( "--csrfile" | "-csr" ) " file:"<input_csr_file> NO_CERTIFICATE_CHAIN ::= (
 * "--nochain" | "-nch" )
 *
 * @author xlakdag
 */
@CommandType(PkiCommandType.SECGWCERTMANAGEMENT)
@Local(CommandHandlerInterface.class)
public class SecurityGatewayManagementGenerateHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    public static final List<String> SUPPORTED_CERT_TYPES = Arrays.asList("OAM", "Traffic");

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    CertificateUtils certutils;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CRLUtils cRLUtils;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of SecGWcertmanagement. Generates certificate for SecurityGateway and downloads zip file with certificate,
     * certificate chain and trusted certificates.
     *
     * @param command
     *
     * @return PkiCommandResponse zip file with certificate, certificate chain and trusted certificates
     */
    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("process method of SecurityGatewayManagementGenerateHandler class");

        PkiCommandResponse commandResponse = null;
        String entityName = null;
        File zipfile = null;
        SecGWCertificates secGwCertificates;
        List<Certificate> trustedcertificates = null;
        String inputFileName = null;
        Boolean isChainRequired = true;
        File certPemFile = null;
        File[] files = null;

        try {

            final String certType = command.getValueString(Constants.CERT_TYPE);
            if (ValidationUtils.isNullOrEmpty(certType) || !SUPPORTED_CERT_TYPES.contains(certType)) {
                return cliUtil.prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR + Constants.SPACE_STRING
                        + PkiErrorCodes.CHECK_ONLINE_HELP, Constants.EMPTY_STRING);
            }
            final String csrData = cliUtil.getFileContentFromCommandProperties(command.getProperties());
            if (ValidationUtils.isNullOrEmpty(csrData)) {
                return cliUtil.prepareErrorMessage(ErrorType.INVALID_CSR_FILE.toInt(), PkiErrorCodes.CSR_FORMAT_ERROR, Constants.EMPTY_STRING);
            }
            final CertificateRequest certificateRequest = CSRUtil.generateCSR(csrData);
            entityName = getEntityNameFromCSR(certificateRequest, certType);
            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return cliUtil.prepareErrorMessage(ErrorType.INVALID_CSR_FILE.toInt(), PkiErrorCodes.CSR_FORMAT_ERROR, Constants.EMPTY_STRING);
            }
            if (command.hasProperty(Constants.NOCHAIN)) {
                isChainRequired = false;
            }
            secGwCertificates = generateSecGwCertificate(entityName, certificateRequest, isChainRequired);
            logger.debug("Certificate is created for SecGW {}", secGwCertificates.getCertificate());
            inputFileName = cliUtil.getFileNameFromCommandProperties(command.getProperties());
            final List<Certificate> certificates = new ArrayList<>();
            if (secGwCertificates.getCertificateChain() != null) {
                certificates.addAll(secGwCertificates.getCertificateChain().getCertificates());
            } else {
                certificates.add(secGwCertificates.getCertificate());
            }
            certPemFile = certutils.createPEMCertificateFile(certificates, inputFileName);
            trustedcertificates = secGwCertificates.getTrustedCertificates();
            files = certutils.createPEMCertificateFiles(trustedcertificates, "trust_");
            for (int i = 0; i < files.length; i++) {
                if (files[i] == null) {
                    files[i] = certPemFile;
                    break;
                }
            }
            zipfile = cRLUtils.createZipFile(files, CliUtil.getTempFile(inputFileName, Constants.ZIP_FILE_EXTENSION));
            final byte[] certsBytes = cRLUtils.convertFiletoByteArray(zipfile);
            commandResponse = cliUtil.buildPkiCommandResponse(inputFileName + Constants.ZIP_FILE_EXTENSION, Constants.CRL_CONTENT_TYPE,
                    certsBytes);
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION
                    + Constants.SPACE_STRING, algorithmNotFoundException);
        } catch (final CertificateException exception) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION
                    + Constants.SPACE_STRING, exception);
        } catch (final com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException certificateException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION
                    + Constants.SPACE_STRING, certificateException);
        } catch (final CommandSyntaxException commandSyntaxException) {
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR + Constants.SPACE_STRING
                    + commandSyntaxException.getMessage(), commandSyntaxException);
        } catch (final CRLException crlException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION
                    + Constants.SPACE_STRING, crlException);
        } catch (final EntityException entityException) {
            return prepareErrorMessage(ErrorType.ENTITY_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION
                    + Constants.SPACE_STRING, entityException);
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CSR_FILE + Constants.SPACE_STRING
                    + illegalArgumentException.getMessage(), illegalArgumentException);
        } catch (final InvalidCertificateRequestException invalidCertificateRequestException) {
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE_REQUEST_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CERTIFICATE_REQUEST
                    + Constants.SPACE_STRING, invalidCertificateRequestException);
        } catch (final IOException iOException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CSR_FILE + Constants.SPACE_STRING,
                    iOException);
        } catch (final ProfileException profileException) {
            return prepareErrorMessage(ErrorType.PROFILE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION
                    + Constants.SPACE_STRING, profileException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION,
                    Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING, exception);
        }
        finally {
           if(files != null) {
            for (int i = 0; i < files.length; i++) {
                if (files[i] != null && files[i].exists()) {
                    files[i].delete();
                }
            }
          }
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.SECGWCERTMANAGEMENT", "SecurityGatewayManagementGenerateHandler",
                "Security gateway certificate generated for entity: " + entityName, "Generate gateway certificate", ErrorSeverity.INFORMATIONAL,
                "SUCCESS");
        return commandResponse;
    }

    private String getEntityNameFromCSR(final CertificateRequest certificateRequest, final String certType)
            throws InvalidCertificateRequestException, IOException {

        String entityName = null;
        final String cnFromCSR = CSRUtil.getCNFromCSR(certificateRequest);

        if (ValidationUtils.isNullOrEmpty(cnFromCSR)) {
            return entityName;
        }
        entityName = cnFromCSR + "_" + certType;
        return entityName;
    }

    private SecGWCertificates generateSecGwCertificate(final String entityName, final CertificateRequest certificateRequest,
            final Boolean isChainRequired) throws AlgorithmNotFoundException, CertificateException, EntityException, IllegalArgumentException,
            InvalidCertificateRequestException, ProfileException, IOException {

        SecGWCertificates certificates = null;
        certificates = eServiceRefProxy.getEntityCertificateManagementCustomService().generateSecGWCertificate(entityName, certificateRequest, isChainRequired);
        return certificates;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while generating secgw certificate with csr {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }
}
