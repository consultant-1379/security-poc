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
package com.ericsson.oss.itpf.security.pki.ra.scep.validator;

import java.security.PublicKey;
import java.security.Security;

import javax.inject.Inject;

import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * This class contains the implementation for validating signature which validates the signature of the PKCS7 message.
 *
 * @author xkarlak
 */
public class SignatureValidator {

    @Inject
    private Logger logger;

    /**
     * This method verifies the signature of the PKCS7 message request received from SCEP client.
     *
     * @param signerInformation
     *            is the signerInformation field of the PKCS7 message which contains the signature to be verified.
     * @param publickey
     *            is the SCEP client public key by which the signature is verified.
     * @return boolean returns true/false based on the verification.
     */
    @Profiled
    public boolean validateSignature(final SignerInformation signerInformation, final PublicKey publickey) {
        logger.debug("verifySignature method of SignatureValidator");
        ContentVerifierProvider contentVerifierProvider = null;
        DigestCalculatorProvider digestCalculatorProvider = null;
        boolean verifySign = false;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)).build(publickey);
            digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        } catch (final OperatorCreationException e) {
            logger.error("Caught Exception while verifying ", e.getMessage());
            return verifySign;
        }
        final DefaultSignatureAlgorithmIdentifierFinder defaultSigAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        final DefaultCMSSignatureAlgorithmNameGenerator defaultAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        final SignerInformationVerifier signerInformationVerifier = new SignerInformationVerifier(defaultAlgorithmNameGenerator, defaultSigAlgorithmIdentifierFinder, contentVerifierProvider,
                digestCalculatorProvider);
        try {
            verifySign = signerInformation.verify(signerInformationVerifier);
        } catch (final CMSException e) {
            logger.error("Verification of signature on the message failed");
            return verifySign;
        }
        logger.debug("End of verifySignature method of SignatureValidator");
        return verifySign;
    }

}
