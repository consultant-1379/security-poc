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
package com.ericsson.oss.itpf.security.pki.common.validator;

import java.security.*;

/**
 * SignatureValidator class is used to validate the signature.
 * 
 * @author tcsramc
 * 
 */
public class SignatureValidator {

    private SignatureValidator() {

    }

    /**
     * This method is used to validate the signature from the request Message using public key
     * 
     * @param algorithm
     *            Algorithm used to validate signature.
     * @param publicKey
     *            Key used to validate signature.
     * @param data
     * @param signatureBytes
     *            to validate.
     * @return
     * @throws SignatureException
     *             is thrown if signature is invalid.
     * @throws NoSuchAlgorithmException
     *             is thrown if invalid aligorthm used.
     * @throws InvalidKeyException
     *             is thrown if key is inavlid.
     */
    public static boolean validate(final String algorithm, final PublicKey publicKey, final byte[] data, final byte[] signatureBytes) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        final Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
