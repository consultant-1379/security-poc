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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.common.validator.SignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;

/**
 * Validates Digital Signature of the Message:<br>
 * 1. Within the RequestMessage there will be UserCertificate and it chain.
 * Signature needs to be validated for both.<br>
 * 2. In case of user certificate, based on the public key of the
 * userCertificate validate the protectionBytes.<br>
 * 3. In case of chain, PKIXCertpathBuilder algorithm is used to build a
 * CertificatePath. In case with the constraints given i.e userCertificate and
 * certificateChain, if path is built properly, it means that digitalSignature
 * is validated.
 *
 * @author tcsdemi
 *
 */
public class DigitalSignatureValidator implements RequestValidator {

    @Inject
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Inject
    InitialConfiguration configurationData;

    @Inject
    Logger logger;

    @Inject
    TrustStoreUtil trustStore;

    @Override
    public void validate(final RequestMessage pKIRequestMessage) throws DigitalSignatureValidationException {

        logger.info("Digital Signature Validation started for: {} ", pKIRequestMessage.getRequestMessage());
        try {
            final Set<X509Certificate> trustedCertificates = trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage);

            final StringBuilder certsDetail = new StringBuilder();

            certsDetail.append("Trusted CAs available for Validation : ");
            for (X509Certificate certificate : trustedCertificates) {
                certsDetail.append("{ " + certificate.getSubjectDN().getName() + " }");
            }

            final X509Certificate userCertificate = pKIRequestMessage.getUserCertificate();
            certsDetail.append(" Entity certificate Issuer DN : { " + userCertificate.getIssuerDN().getName() + " }");

            final Set<X509Certificate> certificateChain = pKIRequestMessage.getCertChainSet();
            certsDetail.append(" Certificate chains available with Entity Certificate : ");
            for (X509Certificate certificate : certificateChain) {
                certsDetail.append("{ " + certificate.getSubjectDN().getName() + " }");
            }
            logger.info("certificate Details {}", certsDetail);
            validateDigitalSignatureForUserCertificate(pKIRequestMessage, userCertificate);
            validateDigitalSignatureForCertificateChain(userCertificate, certificateChain, trustedCertificates);
        } catch (SignatureException signatureException) {
            throw new DigitalSignatureValidationException(ErrorMessages.DIGITAL_SIGNATURE_ERROR, signatureException);

        } catch (InvalidKeyException invalidKeyException) {
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_PUBLIC_KEY, invalidKeyException);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_ALGORITHM, noSuchAlgorithmException);

        } catch (IOException ioException) {
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_MESSAGE, ioException);

        } catch (CertPathBuilderException certPathBuilderException) {
            throw new DigitalSignatureValidationException(ErrorMessages.CERTIFICATE_PATH_BUILDER_ERROR, certPathBuilderException);

        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_ALGORITHM, invalidAlgorithmParameterException);

        } catch (CertificateException certificateException) {
            throw new DigitalSignatureValidationException(ErrorMessages.CERTIFICATE_EXCEPTION, certificateException);

        } catch (CertificateParseException certificateParsingException) {
            throw new DigitalSignatureValidationException(certificateParsingException.getMessage(), certificateParsingException);

        } catch (InvalidCertificateVersionException invalidCertificateVersionException) {
            throw new DigitalSignatureValidationException(invalidCertificateVersionException.getMessage(), invalidCertificateVersionException);

        } catch (InvalidInitialConfigurationException invalidInitialConfigurationException) {
            throw new DigitalSignatureValidationException(invalidInitialConfigurationException.getMessage(), invalidInitialConfigurationException);

        } catch (MessageParsingException messageParsingException) {
            throw new DigitalSignatureValidationException(messageParsingException.getMessage(), messageParsingException);

        } catch (InvalidMessageException invalidMessageException) {
            throw new DigitalSignatureValidationException(invalidMessageException.getMessage(), invalidMessageException);

        }

    }

    private void validateDigitalSignatureForCertificateChain(final X509Certificate userCertificate, final Set<X509Certificate> intermediateCerts, final Set<X509Certificate> trustedCertificates)
            throws CertPathBuilderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        try {
			pKIXCertificatePathBuilder.build(userCertificate, intermediateCerts, trustedCertificates);
		} catch (CertPathBuilderException certPathBuilderException) {
			logger.error("Unable to find trusted CA certificate to validate entity certificate.");
			throw new DigitalSignatureValidationException(certPathBuilderException.getMessage(),certPathBuilderException);
			
		}
    }

    private void validateDigitalSignatureForUserCertificate(final RequestMessage pKIRequestMessage, final X509Certificate userCertificate) throws DigitalSignatureValidationException,
            InvalidKeyException, SignatureException, NoSuchAlgorithmException, CertificateException {

        boolean isValid = false;
        PublicKey publicKey;
        publicKey = userCertificate.getPublicKey();
        isValid = isSignatureValid(pKIRequestMessage, publicKey);

        if (!isValid) {
            logger.error("Digital Signature Validation failed for Entity : {}", pKIRequestMessage.getRequestMessage());
            throw new DigitalSignatureValidationException(ErrorMessages.DIGITAL_SIGNATURE_ERROR);
        }
    }

    private boolean isSignatureValid(final RequestMessage pKIRequestMessage, final PublicKey publicKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

        boolean isValid = false;
        String protectionAlgorithmId = null;
        byte[] protectedPartFromRequest = null;
        byte[] protectionAsBitStringFromRequest = null;

        protectionAlgorithmId = pKIRequestMessage.getProtectionAlgorithmID();
        protectedPartFromRequest = pKIRequestMessage.getProtectionEncoded();
        protectionAsBitStringFromRequest = pKIRequestMessage.getProtectionBytes();

        isValid = SignatureValidator.validate(protectionAlgorithmId, publicKey, protectedPartFromRequest, protectionAsBitStringFromRequest);
        return isValid;
    }

}
