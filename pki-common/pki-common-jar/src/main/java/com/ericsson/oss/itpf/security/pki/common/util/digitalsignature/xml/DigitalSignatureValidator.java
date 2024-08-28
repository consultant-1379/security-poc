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
package com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Set;

import javax.inject.Inject;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateIsNullException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;

/**
 * This class is used to validate the signature on the message.
 * 
 * @author xnagsow
 *
 */
public class DigitalSignatureValidator {

    @Inject
    private PKIXCertificatePathBuilder pKIXCertificatePathBuilder;
    
    @Inject
    private JaxbUtil jaxbUtil;

    private static final Logger LOGGER = LoggerFactory.getLogger(DigitalSignatureValidator.class);

    /**
     * This method is used to validate XML digital Signature and the certificate which is present in the XML.
     * 
     * @param document
     *            XML Document of which the signature is to be validated.
     * @param certificateSet
     *            Trusted certificate chain to validate the certificate which is present in the XML and it is used to verify the signature.
     * @throws DigitalSignatureValidationException
     *             is thrown when the signature on the XML is not valid.
     */
    public void validate(final Document document, final Set<X509Certificate> certificateSet) throws DigitalSignatureValidationException {
        try {
            validateCertificateChain(document, certificateSet);

            if (!isValidSignatureOnXML(document)) {
                LOGGER.error(ErrorMessages.INVALID_DIGITAL_SIGNATURE);
                throw new DigitalSignatureValidationException(ErrorMessages.INVALID_DIGITAL_SIGNATURE);
            }
        } catch (CertPathBuilderException certPathBuilderException) {
            LOGGER.error("Error while building certificate path due to invalid parameters {}", certPathBuilderException);
            throw new DigitalSignatureValidationException(ErrorMessages.CERTIFICATE_PATH_BUILDER_ERROR + certPathBuilderException);

        } catch (CertificateIsNullException | IOException | CertificateException invalidCertificateChainException) {
            LOGGER.error("Invalid certificate chain {}", invalidCertificateChainException);
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_CERTIFICATE_CHAIN + invalidCertificateChainException);

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException invalidAlgorithmException) {
            LOGGER.error("Algorithm is not supported by the provider to perform the certificate path validation {}", invalidAlgorithmException);
            throw new DigitalSignatureValidationException(ErrorMessages.INVALID_ALGORITHM + " by the provider to perform the certificate path validation", invalidAlgorithmException);

        } catch (MarshalException marshalException) {
            LOGGER.error("Failed to marshal java XML object to document {}", marshalException);
            throw new DigitalSignatureValidationException(ErrorMessages.FAILED_TO_MARSHALL + marshalException);

        } catch (XMLSignatureException xMLSignatureException) {
            LOGGER.error("Failed to sign the xml {}", xMLSignatureException);
            throw new DigitalSignatureValidationException(ErrorMessages.FAILED_TO_SIGN + xMLSignatureException);
        }
    }

    private boolean isValidSignatureOnXML(final Document document) throws MarshalException, XMLSignatureException {
        final NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, Constants.SIGNATURE);
        final DOMValidateContext valueContext = new DOMValidateContext(new X509KeySelector(), nodeList.item(0));
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance(Constants.MECHANISM_TYPE);
        final XMLSignature signature = fac.unmarshalXMLSignature(valueContext);
        return signature.validate(valueContext);
    }

    private void validateCertificateChain(final Document document, final Set<X509Certificate> certificateSet) throws IOException, CertificateException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, CertPathBuilderException, CertificateIsNullException {
        final X509Certificate cert = jaxbUtil.getX509CertificateFromDocument(document);
        pKIXCertificatePathBuilder.build(cert, null, certificateSet);
    }

    

}
