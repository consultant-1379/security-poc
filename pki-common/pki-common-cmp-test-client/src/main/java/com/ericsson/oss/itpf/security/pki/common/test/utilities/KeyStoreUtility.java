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
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.io.FileReader;
import java.io.IOException;
import java.security.*;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;


public class KeyStoreUtility {

    public static KeyPair generateKeyPair(final String keyAlgorithm, final int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        keyGen.initialize(keySize);
        final KeyPair keyPair = keyGen.genKeyPair();
        return keyPair;
    }

    public static KeyPair getKeys(final String keyFile) throws IOException {
        try(final PEMParser pemParser = new PEMParser(new FileReader(keyFile))){
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(Constants.BC_SECURITY_PROVIDER);
        final Object object = pemParser.readObject();
        KeyPair keyPair = null;
        if ((object != null) && (object instanceof PEMKeyPair)) {
            keyPair = converter.getKeyPair((PEMKeyPair) object);
        }
        return keyPair;
    }
    }
}
