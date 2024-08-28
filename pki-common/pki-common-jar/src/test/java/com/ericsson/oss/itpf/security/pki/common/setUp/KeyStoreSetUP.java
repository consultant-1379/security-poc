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
package com.ericsson.oss.itpf.security.pki.common.setUp;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.junit.Assert;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;

/**
 * This class is used to set up test data required for other Junit Test cases.
 * 
 * @author tcshepa
 * 
 */
public class KeyStoreSetUP {

    private String aliasName = "lteipsecnecus";
    private String filePath = "src/test/resources/LTEIPSecNEcus_Sceprakeystore_1.p12";
    private String password = "C4bCzXyT";

    /**
     * Method to generate KeyStoreInfo by passing fileType and aliasName.
     * 
     * @param fileType
     * @param aliasName
     * @return keyStore
     */
    public KeyStoreInfo getKeyStoreInfo(String fileType, String aliasName) {

        final KeyStoreInfo keyStore = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), password, aliasName);

        return keyStore;
    }

    /**
     * Method to loadKeyStore by passing KeyStoreInfo Object.
     * 
     * @param keyStoreInfo
     * @return keyStore
     * @throws KeyStoreException
     * @throws IOException
     * @throws FileNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */

    public static KeyStore loadKeyStore(final KeyStoreInfo keyStoreInfo) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {

        KeyStore keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());

        keyStore.load(new FileInputStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());

        return keyStore;
    }

    /**
     * Method to get Certificate by passing KeyStoreInfo Object.
     * 
     * @param keyStoreInfo
     * @return certificate
     * @throws IOException
     * @throws FileNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public Certificate getCertificate(KeyStoreInfo keyStoreInfo) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        KeyStore keystore = loadKeyStore(keyStoreInfo);

        Certificate certificate = keystore.getCertificate(aliasName);

        return certificate;

    }

    /**
     * Method to get CertificateChain by passing KeyStoreInfo Object.
     * 
     * @param keyStoreInfo
     * @return certificate array
     * @throws IOException
     * @throws FileNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public Certificate[] getCertificateChain(KeyStoreInfo keyStoreInfo) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        KeyStore keystore = loadKeyStore(keyStoreInfo);

        Certificate[] certificate = keystore.getCertificateChain(aliasName);

        return certificate;

    }

    public String readFile(String filePath) {
        final File file = new File(filePath);
        String filepath = file.getAbsolutePath();
        BufferedReader br = null;
        String line = null;
        StringBuilder sb = new StringBuilder();
        try {
            File file1 = new File(filepath);
            FileReader fr = new FileReader(file1);
            br = new BufferedReader(fr);

            while ((line = br.readLine()) != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
        } catch (IOException e) {
            Assert.fail("IOException occured in reading content");
        } finally {
            try {
                br.close();
            } catch (IOException e) {
                Assert.fail("IOException occured while closing Reader");
            }
        }
        return sb.toString();
    }

}
