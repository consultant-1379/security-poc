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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.io.IOException;
import java.security.*;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.HeaderBuilder;
import com.ericsson.oss.itpf.security.pki.common.model.PKIGeneralName;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

/**
 * This class signs the Response Message to be sent back to entity.
 * 
 * @author tcsdemi
 *
 */
public class ResponseSigner {

    private final Logger logger = LoggerFactory.getLogger(ResponseSigner.class);

    /**
     * This method signs the response message.
     * 
     * @param signKey
     *            This is the privateKey with which the message is signed.
     * @param issuerName
     *            This is the issuerName which is RA-service. Input is given as
     *            String which is then converted to PKIGeneralName.
     * @param responsePKIMessage
     *            ResponseMessage which needs to be signed.
     * @param signatureAlgorithm
     *            SignatureAlgorithm is used to sign the response message.
     * @return
     * @throws IOException
     *             This exception occurs when signedResponse BER/DER encoded
     *             bytes are to be returned and there is some error while
     *             encoding the responseMessage.
     * @throws ProtectionEncodingException
     *             This exception occurs when protectionPart BER/DER encoded
     *             bytes are to be returned and there is some error while
     *             encoding the protectionPart.
     * @throws ResponseSignerException
     *             This is a wrapper exception in case there are any other
     *             generic checked exceptions which can be thrown.
     */
    public byte[] sign(final PrivateKey signKey, final String issuerName, final ResponseMessage responsePKIMessage, final String signatureAlgorithm) throws IOException, ProtectionEncodingException, ResponseSignerException {

        final AlgorithmIdentifier algorithmIdentifier = responsePKIMessage.getProtectionAlgorithm();
        final PKIGeneralName senderName = StringUtility.toGeneralName(issuerName);

        final PKIHeaderBuilder pKIHeaderBuilder = HeaderBuilder.create(responsePKIMessage.getResponsePKIHeader(), senderName);
        pKIHeaderBuilder.setProtectionAlg(algorithmIdentifier);

        final PKIHeader responseHeader = pKIHeaderBuilder.build();
        final PKIBody responseBody = responsePKIMessage.getPKIResponseMessage().getBody();
        final CMPCertificate[] extraCerts = responsePKIMessage.getPKIResponseMessage().getExtraCerts();
        DERBitString derBitSignature = null;
        try {
            final ProtectedPart protectedPart = new ProtectedPart(responseHeader, responseBody);
            final Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(signKey);
            signature.update(protectedPart.getEncoded());
            derBitSignature = new DERBitString(signature.sign());

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throwCustomException(ErrorMessages.INVALID_ALGORITHM, noSuchAlgorithmException);

        } catch (InvalidKeyException invalidKeyException) {
            throwCustomException(ErrorMessages.INVALID_PRIVATE_KEY, invalidKeyException);

        } catch (SignatureException signatureException) {
            throwCustomException(ErrorMessages.INVALID_RESPONSE, signatureException);

        } catch (IOException ioException) {
            throw new ProtectionEncodingException(ErrorMessages.PROTECTION_ENCODING_ERROR, ioException);

        }
        final PKIMessage signedResponse = new PKIMessage(responseHeader, responseBody, derBitSignature, extraCerts);

        return signedResponse.getEncoded();
    }

    private void throwCustomException(final String errorMessage, final Throwable cause) throws ResponseSignerException {
        logger.error(errorMessage);
        throw new ResponseSignerException(errorMessage, cause);

    }

}
