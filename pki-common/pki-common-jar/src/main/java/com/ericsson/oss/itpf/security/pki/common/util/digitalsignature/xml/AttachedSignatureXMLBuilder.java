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

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.*;

/**
 * This class is used to build the digitally signed XML object using the provided signer certificate and signer private key..
 * 
 * @author xnagsow
 *
 */
public class AttachedSignatureXMLBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(AttachedSignatureXMLBuilder.class);

    private AttachedSignatureXMLBuilder() {

    }

    /**
     * This method will digitally sign the xml object using the provided signer certificate and signer private key and prepares the attached digital signature XML.
     * 
     * @param signerCertificate
     *            Certificate of the Signer.
     * @param signerPrivateKey
     *            Key used to sign the xml.
     * @param classT
     *            xml is to be signed.
     * @return byte array form of signed xml.
     * @throws DigitalSigningFailedException
     *             is thrown when failed to sign the xml.
     * @throws MarshalException
     *             is thrown when failed o marshal the data into document.
     */
    public static <T> byte[] build(final X509Certificate signerCertificate, final PrivateKey signerPrivateKey, final T classT) throws DigitalSigningFailedException, MarshalException {
        byte[] signedXML = null;
        try {

            final XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(Constants.MECHANISM_TYPE);
            final String keyAlgorithm = signerCertificate.getPublicKey().getAlgorithm();
            final SignedInfo signedInfo = buildSignedInfo(signatureFactory, keyAlgorithm);
            final KeyInfo keyInfo = getKeyInfo(signerCertificate, signatureFactory);

            final Document document = JaxbUtil.getXML(classT);
            sign(signerPrivateKey, signatureFactory, signedInfo, keyInfo, document);
            signedXML = DOMUtil.getByteArray(document);

        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            LOGGER.error("Algorithm is not supported by Java.security {}", invalidAlgorithmParameterException.getMessage());
            throw new DigitalSigningFailedException(ErrorMessages.INVALID_ALGORITHM, invalidAlgorithmParameterException);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error("No such Algorithm is defined {}", noSuchAlgorithmException.getMessage());
            throw new DigitalSigningFailedException(ErrorMessages.NO_SUCH_ALGORITHM, noSuchAlgorithmException);

        } catch (XMLSignatureException xMLSignatureException) {
            LOGGER.error("Exception in XML signing process {}", xMLSignatureException.getMessage());
            throw new DigitalSigningFailedException(ErrorMessages.FAILED_TO_SIGN, xMLSignatureException);

        } catch (XMLException xMLException) {
            LOGGER.error("Fail to process document for the given xml {}", xMLException.getMessage());
            throw new DigitalSigningFailedException(xMLException.getMessage(), xMLException);

        }
        return signedXML;
    }

    private static void sign(final PrivateKey signerKey, final XMLSignatureFactory signatureFactory, final SignedInfo signedInfo, final KeyInfo keyInfo, final Document document)
            throws MarshalException, XMLSignatureException {
        final DOMSignContext signatureContext = new DOMSignContext(signerKey, document.getDocumentElement());
        try {
            signatureFactory.newXMLSignature(signedInfo, keyInfo).sign(signatureContext);
        } catch (javax.xml.crypto.MarshalException e) {
            LOGGER.error("Failed to marshal java object to document {}", e.getMessage());
            throw new MarshalException(ErrorMessages.FAILED_TO_MARSHALL, e);
        }
    }

    /**
     * This method will build SignedInfo by using the provided XMLSignatureFactory instance.
     * 
     * @param signatureFactory
     *            is the instance of XMLSignatureFactory for the given XML mechanism type.
     * @return SignedInfo XML SignedInfo.
     * @throws NoSuchAlgorithmException
     *             is thrown when algorithm is not supported be the security provider.
     * @throws InvalidAlgorithmParameterException
     *             is thrown for invalid or inappropriate algorithm parameters.
     */
    private static SignedInfo buildSignedInfo(final XMLSignatureFactory signatureFactory, final String keyAlgorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final Transform transform = signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        final List<Transform> transformList = Collections.singletonList(transform);
        final DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
        final Reference reference = signatureFactory.newReference("", digestMethod, transformList, null, null);
        final List<Reference> referenceList = Collections.singletonList(reference);
        SignatureMethod signatureMethod = null;
        if (keyAlgorithm.equalsIgnoreCase(Constants.RSA_ALGORITHM)) {
            signatureMethod = signatureFactory.newSignatureMethod(Constants.RSA_ALGORITHM_URI, null);
        } else if (keyAlgorithm.equalsIgnoreCase(Constants.DSA_ALGORITHM)) {
            signatureMethod = signatureFactory.newSignatureMethod(Constants.DSA_ALGORITHM_URI, null);
        } else if (keyAlgorithm.equalsIgnoreCase(Constants.ECDSA_ALGORITHM)) {
            signatureMethod = signatureFactory.newSignatureMethod(Constants.ECDSA_ALGORITHM_URI, null);
        }
        final CanonicalizationMethod canonicalizationMethod = signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        final SignedInfo signedInfo = signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, referenceList);
        return signedInfo;
    }

    private static KeyInfo getKeyInfo(final X509Certificate certificate, final XMLSignatureFactory signatureFactory) {
        final KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        final X509Data x509Dta = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Dta));
        return keyInfo;
    }

}
