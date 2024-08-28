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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameMultipleValueAndTableCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameMultipleValueCommandResponse;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.ExtCACrlInfo;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

/**
 * Handler implementation for CertificateManagementListExtCA. This provides service to List certificate(s) for CA entity based on status
 *
 * "pkiadm" "extcalist" ("--name" | "-n") EXT_CA__NAME
 *
 *
 */

@CommandType(PkiCommandType.EXTERNALCALIST)
@Local(CommandHandlerInterface.class)
public class CertificateManagementListExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    final String[] certificateHeader = { "Subject", "Issuer", "Validity", "Serial Number", "CRL", "AutoUpdate CRL", "Trust Profiles" };
    final String[] crlHeader = { "Next Update", "Update Url", "Last Update" };

    /**
     * Method implementation of CertificateManagementListExtCAHandler. Handles command to list certificate(s) issued by External CA
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("EXTERNALCALIST command handler");
        final List<String> caNameList = new ArrayList<>();
        final Map<String, List<Certificate>> response = new HashMap<>();
        final Map<String, List<Boolean>> responseCrl = new HashMap<>();
        final Map<String, List<String>> responseTP = new HashMap<>();
        final Map<String, List<ExtCACrlInfo>> responseCrlInfo = new HashMap<>();

        try {
            if (command.hasProperty(Constants.NAME)) {
                final String caName = command.getValueString(Constants.NAME);
                caNameList.add(caName);
                // TODO change the output
                responseCrlInfo.put(caName, getCrlInfo(caName));

            } else {
                final List<ExtCA> extCas = eServiceRefProxy.getExtCaManagementService().getExtCAs();
                logger.info("EXTERNALCALIST command handler: ext CAS ");
                for (final ExtCA extCa : extCas) {
                    logger.info(" 		:  " + extCa.getCertificateAuthority().getName());
                    caNameList.add(extCa.getCertificateAuthority().getName());
                }
            }
            for (final String caName : caNameList) {
                List<Certificate> certificateList = null;
                certificateList = eServiceRefProxy.getExtCaCertificateManagementService().listCertificates_v1(caName, CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED,
                        CertificateStatus.INACTIVE);
                if (certificateList == null || certificateList.isEmpty()) {
                    throw new CertificateNotFoundException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
                }
                response.put(caName, certificateList);
                responseCrl.put(caName, getCrlValue(caName));
                responseTP.put(caName, eServiceRefProxy.getExtCaManagementService().getTrustProfileByExtCA(caName));

            }

        } catch (final CertificateServiceException certificateServiceException) {
            logger.error(PkiErrorCodes.UNABLE_LIST_CERTIFICATE, certificateServiceException.getMessage());
            logger.debug(PkiErrorCodes.UNABLE_LIST_CERTIFICATE, certificateServiceException);
            return prepareErrorMessage(ErrorType.ENTITY_CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.UNABLE_LIST_CERTIFICATE + Constants.SPACE_STRING + PkiErrorCodes.SERVICE_ERROR
                    + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final EntityNotFoundException | ExternalCANotFoundException notFoundEx) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, notFoundEx.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, notFoundEx);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + notFoundEx.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final CertificateNotFoundException e2) {
            logger.error(PkiErrorCodes.NO_CERTIFICATE_FOUND, e2.getMessage());
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, e2);
            return prepareErrorMessage(ErrorType.ENTITY_CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND, "Error on retrieve certificates");
        } catch (final InvalidEntityException invalidEntityException) {
            logger.error(PkiErrorCodes.INVALID_ENTITY, invalidEntityException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY, invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.error(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException.getMessage());
        } catch (final ExternalCredentialMgmtServiceException externalCredMServEx) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, externalCredMServEx.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, externalCredMServEx);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, externalCredMServEx);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        systemRecorder.recordEvent("PKISERVICE.EXTERNALCASERVICE", EventLevel.COARSE, "PKI.EXTERNALCALIST", "External CA listed: " + caNameList.toString(), "External CA listed successfully");
        return buildPkiCommandResponse(response, responseCrl, responseTP, responseCrlInfo);
    }

    private List<ExtCACrlInfo> getCrlInfo(final String caName) {

        final List<ExtCACrlInfo> crlInfoList = new ArrayList<>();
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caName);
        extCA.setCertificateAuthority(certificateAuthority);

        final ExtCA actualExtCa = eServiceRefProxy.getExtCaManagementService().getExtCA(extCA);
        if (actualExtCa.getExternalCRLInfo() != null && actualExtCa.getExternalCRLInfo().getX509CRL() != null) {
            crlInfoList.add(getCrlInfo(actualExtCa));
        }
        if (actualExtCa.getAssociated() != null) {
            for (final ExtCA associated : actualExtCa.getAssociated()) {
                if (associated.getExternalCRLInfo().getX509CRL() != null) {
                    crlInfoList.add(getCrlInfo(associated));
                }
            }
        }
        return crlInfoList;
    }

    private ExtCACrlInfo getCrlInfo(final ExtCA actualExtCa) {
        final ExtCACrlInfo crlInfo = new ExtCACrlInfo();

        crlInfo.setResponseCrlIssuer(actualExtCa.getExternalCRLInfo().getX509CRL().retrieveCRL().getIssuerDN().getName());
        final Date nextUpdate = actualExtCa.getExternalCRLInfo().getNextUpdate();
        if (nextUpdate.compareTo(new Date(0)) == 0) {
            crlInfo.setNextUpdate(actualExtCa.getExternalCRLInfo().getX509CRL().retrieveCRL().getNextUpdate());
        } else {
            crlInfo.setNextUpdate(nextUpdate);
        }

        crlInfo.setUpdateUrl(actualExtCa.getExternalCRLInfo().getUpdateURL());
        crlInfo.setThisUpdate(actualExtCa.getExternalCRLInfo().getX509CRL().retrieveCRL().getThisUpdate());
        return crlInfo;
    }

    /**
     * @param caName
     * @return List<Boolean>
     */

    private List<Boolean> getCrlValue(final String caName) throws ExternalCANotFoundException, ExternalCredentialMgmtServiceException {
        final List<Boolean> crlValues = new ArrayList<>();
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setName(caName);
        extCA.setCertificateAuthority(certificateAuthority);
        final ExtCA actualExtCa = eServiceRefProxy.getExtCaManagementService().getExtCA(extCA);
        Boolean crlValue = false;
        if (actualExtCa.getExternalCRLInfo() != null && actualExtCa.getExternalCRLInfo().getX509CRL() != null) {
            crlValue = true;
        }
        crlValue = crlValue || ((actualExtCa.getAssociated() != null) && (!(actualExtCa.getAssociated().isEmpty())));
        crlValues.add(crlValue);
        Boolean autoUpdate = false;
        if (actualExtCa.getExternalCRLInfo() != null) {
            autoUpdate = actualExtCa.getExternalCRLInfo().isAutoUpdate();
        } else if (actualExtCa.getAssociated() != null && (!(actualExtCa.getAssociated().isEmpty())) && actualExtCa.getAssociated().get(0).getExternalCRLInfo() != null) {
            autoUpdate = actualExtCa.getAssociated().get(0).getExternalCRLInfo().isAutoUpdate();
        }
        crlValues.add(autoUpdate);
        return crlValues;
    }

    private PkiCommandResponse buildPkiCommandResponse(final Map<String, List<Certificate>> response, final Map<String, List<Boolean>> responseCrl, final Map<String, List<String>> responseTP,
            final Map<String, List<ExtCACrlInfo>> responseCrlInfo) {

        final PkiNameMultipleValueAndTableCommandResponse commandResponseTable = new PkiNameMultipleValueAndTableCommandResponse();

        final PkiNameMultipleValueCommandResponse commandResponseCerts = new PkiNameMultipleValueCommandResponse(certificateHeader.length);
        commandResponseCerts.setAdditionalInformation(Constants.LIST_OF_CERTIFICATES);
        commandResponseCerts.add(Constants.EXT_CA_NAME, certificateHeader);

        for (final Map.Entry<String, List<Certificate>> entry : response.entrySet()) {
            for (final Certificate certificate : entry.getValue()) {
                final Boolean crlValue = responseCrl.get(entry.getKey()).get(0);
                final Boolean autoUpdate = responseCrl.get(entry.getKey()).get(1);
                final List<String> trustProfile = responseTP.get(entry.getKey());
                commandResponseCerts.add(entry.getKey(), getCertificateDetails(certificate, crlValue, autoUpdate, trustProfile));

            }
        }
        commandResponseTable.add(commandResponseCerts);

        if (responseCrlInfo != null && !responseCrlInfo.isEmpty()) {
            final PkiNameMultipleValueCommandResponse commandResponseCRL = new PkiNameMultipleValueCommandResponse(crlHeader.length);
            commandResponseCRL.setAdditionalInformation(Constants.LIST_OF_CRLS);
            commandResponseCRL.add(Constants.ISSUER, crlHeader);

            for (final Map.Entry<String, List<ExtCACrlInfo>> entry : responseCrlInfo.entrySet()) {
                for (final ExtCACrlInfo extCACrlInfo : entry.getValue()) {
                    commandResponseCRL.add(extCACrlInfo.getResponseCrlIssuer(), getCrlDetails(extCACrlInfo));
                }
            }
            commandResponseTable.add(commandResponseCRL);
        }
        return commandResponseTable;
    }

    private String[] getCertificateDetails(final Certificate certificate, final Boolean hasCRL, final Boolean autoUpdate, final List<String> trustProfile) {

        StringBuilder trustProfiles = new StringBuilder();
        final DateFormat dateFormat = new SimpleDateFormat(Constants.DATE_FORMAT);
        for (int i = 0; i < trustProfile.size(); i++) {
            trustProfiles = trustProfiles.append(trustProfile.get(i));
            if (i != trustProfile.size() - 1) {
                trustProfiles = trustProfiles.append(",");
            }
        }

        final String certificatesSubjectDn = new X500Name(certificate.getX509Certificate().getSubjectX500Principal().getName()).toString();
        final String certificateIssuerDn = new X500Name(certificate.getX509Certificate().getIssuerX500Principal().getName()).toString();

        final String[] certificateDetails = { certificatesSubjectDn, Constants.EMPTY_STRING + certificateIssuerDn, Constants.EMPTY_STRING + dateFormat.format(certificate.getNotAfter()),
                Constants.EMPTY_STRING + certificate.getSerialNumber(), Constants.EMPTY_STRING + hasCRL, Constants.EMPTY_STRING + autoUpdate, Constants.EMPTY_STRING + trustProfiles };

        return certificateDetails;

    }

    private String[] getCrlDetails(final ExtCACrlInfo extCACrlInfo) {

        final String[] crlDetails = { extCACrlInfo.getNextUpdate(), Constants.EMPTY_STRING + extCACrlInfo.getUpdateUrl(),

        Constants.EMPTY_STRING + extCACrlInfo.getThisUpdate() };

        return crlDetails;

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while listing the certificate: {}", errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while adding the crl: {} ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));
    }

}
