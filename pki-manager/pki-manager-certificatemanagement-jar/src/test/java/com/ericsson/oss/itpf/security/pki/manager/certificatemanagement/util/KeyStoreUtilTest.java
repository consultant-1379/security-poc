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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import static org.junit.Assert.assertTrue;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;

@RunWith(MockitoJUnitRunner.class)
public class KeyStoreUtilTest {

    @InjectMocks
    KeyStoreUtil keyStoreUtil;

    @Mock
    Resource resource;

    @Mock
    Logger logger;

    private static SetUPData setUPData;

    /**
     * Prepares initial set up required to run the test cases.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setUP() {

        setUPData = new SetUPData();
    }

    /**
     * Test case for verifying create keyStore.
     * 
     * @throws CertificateGenerationException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws KeyStoreException
     * @throws SecurityException
     * @throws UnrecoverableKeyException
     */

    @Test
    public void testCreateKeyStore() throws CertificateGenerationException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException, SecurityException,
            UnrecoverableKeyException {

        final char[] password = { 'e', 'n', 't', 'i', 't', 'y' };

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

        final X509Certificate certificate = setUPData.getX509Certificate("certificates/Entity.crt");

        final X509Certificate[] certificateChain = new X509Certificate[] { certificate };

        final String keyStoreFilePath = keyStoreUtil.createKeyStore(password, KeyStoreType.JKS, keyPair, certificateChain, SetUPData.ENTITY_NAME);

        final KeyStore keyStore = loadKeyStore(keyStoreFilePath, password, KeyStoreType.JKS);

        final Key actualPrivateKey = keyStore.getKey(SetUPData.ENTITY_NAME, password);
        assertTrue(Arrays.equals(keyPair.getPrivate().getEncoded(), actualPrivateKey.getEncoded()));

        final java.security.cert.Certificate[] actualCertificate = keyStore.getCertificateChain(SetUPData.ENTITY_NAME);
        assertTrue(Arrays.equals(certificate.getEncoded(), actualCertificate[0].getEncoded()));

    }

    public KeyStore loadKeyStore(final String filePath, final char[] password, final KeyStoreType keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException, SecurityException {
        KeyStore keyStore = null;
        final File keyStoreFile = new File(filePath);
        final FileInputStream fileInputStream = new FileInputStream(keyStoreFile);
        try {
            keyStore = KeyStore.getInstance(keyStoreType.value());
            keyStore.load(fileInputStream, password);
            return keyStore;
        } finally {
            if (keyStoreFile.exists()) {
                keyStoreFile.delete();
            }
            fileInputStream.close();
        }

    }

}
