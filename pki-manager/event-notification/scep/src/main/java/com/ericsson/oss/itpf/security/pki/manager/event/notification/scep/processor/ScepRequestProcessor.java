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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.processor;

import java.io.IOException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.w3c.dom.Document;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ErrorResponse;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepRequest;
import com.ericsson.oss.itpf.security.pki.common.util.Pkcs10RequestParser;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.exception.OTPNotFoundInCSRException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.XMLException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.common.builders.ScepResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.dispatcher.SignedScepResponseMessageDispatcher;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * ScepRequestProcessor class will fetch the data from the SignedScepRequestMessageListener. The class extracts the parameters like OTP, entityName from CSR.
 * 
 * The OTP is validated in the class.
 * 
 * If the validation fails a ScepResponseBuilder will build a SignedScepResponseMessage with FailureInfo.
 * 
 * If the validation is successful then the generateCertificate method will be called, Which will build a Certificate from ScepResponseBuilder for the provided EntityName and CSR. In case of Failure
 * to fetch the certificate an FailureInfo will be dispatched from the SignedScepResponseMessage.
 * 
 * @author xananer
 * 
 */
public class ScepRequestProcessor {

    @Inject
    private ScepResponseBuilder scepResponseBuilder;

    @Inject
    private Pkcs10RequestParser pkcs10RequestParser;

    @Inject
    private Logger logger;

    @Inject
    private CredentialsManager credentialsManager;

    @Inject
    private SignedScepResponseMessageDispatcher scepResponseMessageDispatcher;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    DigitalSignatureValidator digitalSignatureValidator;

    @EJB
    CertificateManagementLocalService certificateManagementLocalService;

    @EJB
    private EntityManagementLocalService entityManagementLocalService;

    /**
     * processRequest will handle the SignedScepRequestMessage and will send the message for processing and dispatches the SignedScepResponseMessage over the ScepResponseMessage Channel
     * 
     * @param signedScepRequestMessage
     *            is the message received over the ScepRequestChannel.
     */

    public void processRequest(final SignedScepRequestMessage signedScepRequestMessage) {
        logger.info("Entering method processRequestHandler of class ScepRequestProcessor ");
        try {
            final SignedScepResponseMessage signedScepResponseMessage = processRequestHandler(signedScepRequestMessage);
            scepResponseMessageDispatcher.sendResponseMessage(signedScepResponseMessage);
            logger.info("End of method processRequestHandler of class ScepRequestProcessor ");
        } catch (final DigitalSigningFailedException e) {
            logger.debug("Error occured while signing SCEP response ", e);
            logger.error(e.getMessage());
        }
    }

    /**
     * processRequestHandler method process the received request message over the ScepRequestChannel and validates the request message and generates the certificate. If the validating of the OTP
     * present in the request message then generates the certificate and dispatches it to the entity.
     * 
     * @param signedScepRequestMessage
     *            is the message received over the ScepRequestChannel.
     * @return scepResponseMessage is the response message for a processed PKCSReq Message over the ScepRequestChannel
     */

    public SignedScepResponseMessage processRequestHandler(final SignedScepRequestMessage signedScepRequestMessage) throws DigitalSigningFailedException {

        logger.info("Entering method processRequest of class ScepRequestProcessor ");
        ScepRequest scepRequest = new ScepRequest();

        String errorCode = null;
        X509Certificate responseCertificate = null;
        String entityName = null;

        int status = ResponseStatus.FAILURE.getStatus();

        try {
            final Document document = DOMUtil.getDocument(signedScepRequestMessage.getScepRequest());
            validateDigitalSignatureForScepRequestMessage(document);
            scepRequest = (ScepRequest) JaxbUtil.getObject(document, ScepRequest.class);
            logger.debug("ScepRequestMessage with transaction Id " + scepRequest.getTransactionId() + " has been received");

            final byte[] csr = scepRequest.getCsr();
            final PKCS10CertificationRequestHolder pKCS10Holder = new PKCS10CertificationRequestHolder(new PKCS10CertificationRequest(csr));

            entityName = fetchEntityName(pkcs10RequestParser.getRequestDN(pKCS10Holder.getCertificateRequest()));

            try {
                final String otp = pkcs10RequestParser.getPassword(pKCS10Holder.getCertificateRequest());

                if (entityManagementLocalService.isOTPValid(entityName, otp)) {
                    final Certificate certificate = generateCertificate(entityName, pKCS10Holder);
                    responseCertificate = certificate.getX509Certificate();
                    status = ResponseStatus.SUCCESS.getStatus();
                } else {
                    errorCode = ErrorResponse.INVALID_OTP.getValue();
                }
            } catch (final EntityNotFoundException e) {
                logger.debug("Error occured while finding the Entity ", e);
                logger.error("Entity not found with name{}", entityName);
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Requested Entity not found in PKCS7SCEP request for entity name:" + entityName);
                errorCode = ErrorResponse.ENTITY_NOT_FOUND.getValue();
            } catch (final InvalidEntityException e) {
                logger.debug("Invalid Entity Exception occured ", e);
                logger.error("Invalid Entity");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Requested Entity is invalid in PKCS7SCEP request for entity name:" + entityName);
                errorCode = ErrorResponse.INVALID_ENTITY.getValue();
            } catch (final OTPExpiredException e) {
                logger.debug("Error occured as OTP expired ", e);
                logger.error("The given OTP is expired");
                systemRecorder.recordSecurityEvent("ScepRequestProcessor", "Scep Request Processor", "The given OTP in PKCS7SCEPRequest expired", "Certificate Generation", ErrorSeverity.ERROR,
                        "FAILURE");
                errorCode = ErrorResponse.OTP_EXPIRED.getValue();
            } catch (final OTPNotFoundInCSRException e) {
                logger.debug("Error occured while fetching OTP from CSR ", e);
                logger.error("OTP not found in the csr");
                errorCode = ErrorResponse.OTP_NOT_FOUND.getValue();
            } catch (final InvalidCertificateRequestException e) {
                logger.debug("Invalid Certificate Request Exception occured ", e);
                logger.error("Invalid CSR");
                systemRecorder.recordSecurityEvent("ScepRequestProcessor", "Scep Request Processor", "Invalid CSR in PKCS7SCEPRequest", "Certificate Generation", ErrorSeverity.ERROR, "FAILURE");
                errorCode = ErrorResponse.INVALID_CSR.getValue();
            } catch (final CertificateGenerationException e) {
                logger.debug("Certificate Generation Exception occured ", e);
                logger.error("Error while generating the certificate.");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Error while generating the certificate in PKCS7SCEP request for entity name:" + entityName);
                errorCode = ErrorResponse.INTERNAL_ERROR.getValue();
            } catch (final CertificateServiceException e) {
                logger.debug("Internal error while validating the Entity and OTP in PKCS7SCEP request ", e);
                logger.error("Internal error while validating the Entity and OTP");
                systemRecorder.recordSecurityEvent("ScepRequestProcessor", "Scep Request Processor", "Internal error while validating the Entity and OTP in PKCS7SCEP request",
                        "Certificate Generation", ErrorSeverity.ERROR, "FAILURE");
                errorCode = ErrorResponse.INTERNAL_ERROR.getValue();
            } catch (final IOException ioException) {
                logger.debug("Error occured while intiating PKCS10CertificationRequest for entity name ", entityName, ioException);
                logger.error("Error during while intiating PKCS10CertificationRequest ");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Error during while intiating PKCS10CertificationRequest for entity name:" + entityName);
                errorCode = ErrorResponse.BAD_REQUEST.getValue();
            } catch (final AlgorithmNotFoundException e) {
                logger.debug("Algorithm not found while generating certificate ", e);
                logger.error("Algorithm not found while generating certificate ");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Algorithm not found while generating certificate for PKCS7SCEPRequest for entity name:" + entityName);
                errorCode = ErrorResponse.AlGORITHM_NOT_FOUND.getValue();
            } catch (final InvalidCAException e) {
                logger.debug("Invalid CA Name during the generation of certificate ", e);
                logger.error("Invalid CA Name during the generation of certificate ");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Algorithm not found while generating certificate for PKCS7SCEPRequest for entity name:" + entityName);
                errorCode = ErrorResponse.INVALID_CA.getValue();
            } catch (final EntityServiceException e) {
                logger.debug("Error occured while generating the certificate for PKCS7SCEPRequest ", e);
                logger.error("Error while generating the certificate.");
                systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                        "Error while generating the certificate for PKCS7SCEPRequest for entity name:" + entityName);
                errorCode = ErrorResponse.INTERNAL_ERROR.getValue();
            }
        } catch (final IOException e) {
            logger.debug("Error occured while intiating PKCS10CertificationRequest ", e);
            logger.error("Error during while intiating PKCS10CertificationRequest ");
            systemRecorder.recordError("PKI_MANAGER_SCEP.PROCESS_SCEP_REQUEST", ErrorSeverity.ERROR, "Generate Certificate", "SCEP Enrollement and SCEP Client",
                    "Error during while intiating PKCS10CertificationRequest");
            errorCode = ErrorResponse.BAD_REQUEST.getValue();
        } catch (final XMLException e) {
            logger.debug("Error occured while marshalling the requested xml message ", e);
            logger.error("Error while getting document from request message.");
            errorCode = ErrorResponse.INTERNAL_ERROR.getValue();
            systemRecorder.recordSecurityEvent("PKI_MANAGER_SCEP", "PKI_MANAGER_SCEP.XMLDigitalSignatureVerifier", "Failed to marshal request xml message ",
                    "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (final DigitalSignatureValidationException e) {
            logger.debug("Error occured while validating the request message for digital signature ", e);
            logger.error("Error while validating the request message for digital signature {}", e.getMessage());
            errorCode = ErrorResponse.SIGNATURE_VERIFICATION_FAILED.getValue();
            systemRecorder.recordSecurityEvent("PKI_MANAGER_SCEP", "PKI_MANAGER_SCEP.XMLDigitalSignatureVerifier", "Failed to validate digital signature on the request xml message ",
                    "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        } catch (final CredentialsManagementServiceException e) {
            logger.debug("Error occured while getting the trust certificates from pki-manager credentials ", e);
            logger.error("Error while getting the trust certificates from pki-manager credentials {}", e.getMessage());
            errorCode = ErrorResponse.INTERNAL_ERROR.getValue();
            systemRecorder.recordSecurityEvent("PKI_MANAGER_SCEP", "PKI_MANAGER_SCEP.XMLDigitalSignVerifier", "Failed to get trust certificates from pki-manager credentials ",
                    "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
        }

        final SignedScepResponseMessage signedScepResponseMessage = scepResponseBuilder.buildScepResponse(scepRequest.getTransactionId(), status, errorCode, responseCertificate);
        logger.info("End of method processRequest of class ScepRequestProcessor ");
        return signedScepResponseMessage;
    }

    /**
     * generateCertificate method generates the certificate for the given scepMessageRequest over the ScepRequestChannel. If the generation of the certificate is successful the method builds the
     * ScepResponseMessage with certificate to the node and sends over the ScepResponseChannel.
     * 
     * If the generation of the certificate failed then the method will build the scepResponseMessage with the appropriate failureInfo and sends the ScepResponseMessage it over the
     * ScepResponseChannel.
     * 
     * @throws EntityNotFoundException
     *             thrown when the entity profile is not present.
     * 
     * @throws InvalidEntityException
     *             thrown when the entity parameters are invalid.
     * 
     * @throws CertificateServiceException
     *             thrown when generation of certificate failed due to a service failure.
     * 
     * @throws InvalidCAException
     *             thrown if the CA is not valid to generate a certificate.
     * 
     * @throws AlgorithmNotFoundException
     *             No Algorithm found during the generation of certificate.
     * 
     * @throws CertificateGenerationException
     *             thrown in case of any exception while generating the certificate.
     * 
     * @throws IOException
     *             thrown if any I/O Error occurs.
     * 
     * @return Certificate is the certificate holder containing the X509Certificate.
     * 
     * 
     */

    private Certificate generateCertificate(final String entityName, final PKCS10CertificationRequestHolder pKCS10Holder) throws AlgorithmNotFoundException, EntityNotFoundException,
            CertificateServiceException, InvalidEntityException, InvalidCAException, InvalidCertificateRequestException, CertificateGenerationException, IOException {
        logger.info("Entering method generateCertificate of class ScepRequestProcessor ");

        final CertificateRequest requestCsr = new CertificateRequest();

        requestCsr.setCertificateRequestHolder(pKCS10Holder);

        logger.info("End of method generateCertificate of class ScepRequestProcessor ");

        return certificateManagementLocalService.generateCertificate(entityName, requestCsr);

    }

    /**
     * fetchEntityName will fetch the entityName from the subjectDN.The subject DN will be in the form of CN=ZZZ. Where ZZZ will be the name of the entityName to be fetched.
     * 
     * @param subjectName
     *            is SubjectDN value fetched from the PKCS10 Message.
     * @return entity is the entityName for which the certificate has to be created.
     */
    private String fetchEntityName(final X500Name subjectName) {

        logger.info("Entering method fetchEntityName of class ScepRequestProcessor ");
        final RDN entityName = subjectName.getRDNs(BCStyle.CN)[0];
        logger.info("End of method fetchEntityName of class ScepRequestProcessor ");
        return entityName.getFirst().getValue().toString();

    }

    private void validateDigitalSignatureForScepRequestMessage(final Document document) throws DigitalSignatureValidationException, CredentialsManagementServiceException

    {
        logger.debug("validateDigitalSignatureForScepRequestMessage method in ScepRequestProcessor class");
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = JaxbUtil.getX509CertificateFromDocument(document);
            certificateManagementLocalService.validateCertificateChain(x509Certificate);
            logger.debug("Chain validation completed successfully on request message");
        } catch (final CertificateNotFoundException e) {
            logger.debug("Error occured in finding the received scep signer certificate ", e);
            logger.error(e.getMessage());
            systemRecorder.recordSecurityEvent("PKI_MANAGER_SCEP", "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", "The received scep signer certificate is not found in the system ",
                    "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
            throw new DigitalSignatureValidationException(e.getMessage());
        } catch (final RevokedCertificateException e) {
            logger.debug("Error occured while validating the Certificate Chain on request message ", e);
            logger.error("Certificate Chain Validation failed");
            systemRecorder.recordSecurityEvent("PKI_MANAGER_SCEP", "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", "Certificate Chain validation failed on request message ",
                    "PKI_MANAGER_SCEP.XMLDigitalSignatureVerification", ErrorSeverity.CRITICAL, "FAILURE");
            throw new DigitalSignatureValidationException(e.getMessage());
        } catch (final CertificateServiceException e) {
            logger.debug("Certificate Service Exception occured while validating Digital Signature for SCEP request message ", e);
            logger.error(e.getMessage());
            throw new DigitalSignatureValidationException(e.getMessage());
        } catch (final CertificateException | IOException e) {
            logger.debug("Certificate Exception or IOException occured while validating Digital Signature for SCEP request message ", e);
            logger.error(e.getMessage());
            throw new DigitalSignatureValidationException(e.getMessage());
        } catch (final Exception exception) {
            logger.debug("ERROR IN PROCESSING THE REQUEST SENT FROM SCEP ", exception);
            logger.error("ERROR IN PROCESSING THE REQUEST SENT FROM SCEP {}", exception.getCause());

        }
        digitalSignatureValidator.validate(document, credentialsManager.getTrustCertificateSet());
    }
}
