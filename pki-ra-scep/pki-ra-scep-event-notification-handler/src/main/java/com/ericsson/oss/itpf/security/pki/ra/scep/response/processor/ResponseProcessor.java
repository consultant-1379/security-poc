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
package com.ericsson.oss.itpf.security.pki.ra.scep.response.processor;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DOMException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.XMLException;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateChainCRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateRevokeValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.SCEPLocalService;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * ResponseProcessor will process the SCEP response for a PKCSReq message and persists response message.
 * 
 * @author xtelsow
 */

public class ResponseProcessor {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private DigitalSignatureValidator digitalSignatureValidator;

    @Inject
    ConfigurationListener configurationListener;

    @Inject
    private CertificateChainCRLValidator certificateChainCRLValidator;

    @Inject
    private CertificateRevokeValidator certificateRevokeValidator;

    @Inject
    private ScepCrlCacheUtil scepCrlCacheUtil;

    @EServiceRef
    SCEPLocalService scepLocalService;

    /**
     * processResponse method will fetch entityManager and updates the SCEP response for a given PKCSReq message and persists the response message.
     * 
     * @param signedScepResponseMessage
     *            is the responseMessage for a given PkcsReqMessaage.
     */

    public void processResponse(final SignedScepResponseMessage signedScepResponseMessage) {
        logger.debug("In Process Response method for ScepResponseMessage");
        ScepResponse scepResponse = null;
        try {
            scepResponse = validateAndLoadResponseData(signedScepResponseMessage.getScepResponse());
            scepLocalService.updateSCEPResponseStatus(scepResponse);
            logger.info("End of Process Response method for ScepResponseMessage");
        } catch (DigitalSignatureValidationException e) {
            logger.error("Digital signature validation failed on response message");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Digital signature verification failed during secure communication of SPS and RA",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (XMLException e) {
            logger.error("Failed to marshal the xml document");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier",
                    "Failed to process messages(xml marshal) from SPS and RA while secure communication", "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (PkiScepServiceException e) {
            logger.error(e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Unable to read certificate from the trust store of Registration Authority",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (CertificateRevokedException e) {
            logger.error("Entity Certificate is Revoked");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier",
                    "Certificate of SPS has been revoked as part of secure communication with Registration Authority", "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL,
                    "FAILURE");
        } catch (CRLValidationException e) {
            logger.error("CRL validation is failed");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Registration Authority certificate CRL validation is failed ",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (CertificateException e) {
            logger.error("Certificate conversion is unable to be made");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Processing Certificate failed while exchaingnig certificate from SPS",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (KeyStoreException e) {
            logger.error("Unable to read public key form trusted CA certificate");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Unable to read public key form trusted CA certificate",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (IOException e) {
            logger.error("In the event of corrupted data, or an incorrect structure during reading of certificate/CRL");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.XMLDigitalSignatureVerifier", "Processing of certificate/CRL failed during secure communication",
                    "PKIRASCEPService.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        }
    }

    /**
     * This method is used to validate the digital signature on the received SCEP XML Response. Up on Successful validation, it will prepare the ScepResponseXMl object with values received in the xml
     * response. Up on validation failure, it will prepare the ScepResponseXMl with status as Failure and with corresponding failure info.
     * 
     * @param byte[] scepResponseByteArray is the digitally signed scep response message in the form of byte array.
     * @return ScepResponse is the response data holder which will set upon successful xml validation of ScepResponseMessage.
     * @throws IOException
     *             In the event of corrupted data, or an incorrect structure.
     * @throws CertificateException
     *             If the Certificate conversion is unable to be made.
     * @throws KeyStoreException
     *             if Unable to read public key form trusted CA certificate
     * @throws CRLValidationException
     *             This exception will handle certificateException(is thrown if no Provider supports a CertificateFactory implementation for the specified type.) and CRLException(is thrown if any
     *             parsing errors occurs while generating CRL)
     * @throws CertificateRevokedException
     *             throws if Entity Certificate is Revoked
     */
    private ScepResponse validateAndLoadResponseData(final byte[] scepResponseByteArray) throws PkiScepServiceException, DigitalSignatureValidationException, DOMException, CertificateException,
            IOException, CRLValidationException, KeyStoreException, CertificateRevokedException {
        logger.info("Validating the signature on the SCEP XML Response");

        if (scepResponseByteArray == null) {
            logger.error("Invalid scep response message");
            throw new PkiScepServiceException(ErrorMessages.INVALID_SCEP_RESPONSE);
        }
        ScepResponse scepResponse = null;
        final Document document = DOMUtil.getDocument(scepResponseByteArray);
        digitalSignatureValidator.validate(document, cryptoService.readAllCertificates(true));
        validateCertificateWithCRL(document);
        scepResponse = (ScepResponse) JaxbUtil.getObject(document, ScepResponse.class);
        logger.debug("Digital Signature is validated successfully and loaded the response data for the scep transaction with id " + scepResponse.getTransactionId() + " was received");
        logger.info("End of validate signature on the SCEP XML Response");
        return scepResponse;
    }

    private void validateCertificateWithCRL(final Document document) throws CertificateException, IOException, CRLValidationException, PkiScepServiceException, KeyStoreException,
            CertificateRevokedException {
        logger.info("validateCertificateWithCRL method in ResponseProcessor class");
        final X509Certificate cert = JaxbUtil.getX509CertificateFromDocument(document);
        final String issuerName = CertificateUtility.getIssuerName(cert);
        final X509CRL issuerCRL = scepCrlCacheUtil.getCRL(issuerName);
        certificateChainCRLValidator.validateIssuerCRL(cert, issuerCRL, issuerName, null, cryptoService.readAllCertificates(true));
        certificateRevokeValidator.validate(cert, issuerCRL);
        logger.info("End of validateCertificateWithCRL method in ResponseProcessor class");
    }

}