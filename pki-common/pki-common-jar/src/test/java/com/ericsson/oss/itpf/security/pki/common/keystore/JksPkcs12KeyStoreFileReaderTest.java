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
 *---------------------------------------------------------------------------- */
package com.ericsson.oss.itpf.security.pki.common.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.exception.AliasNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.InvalidKeyStoreDataException;
import com.ericsson.oss.itpf.security.pki.common.setUp.KeyStoreSetUP;

/**
 * This class is a junit test class for JksPkcs12KeyStoreFileReader
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class JksPkcs12KeyStoreFileReaderTest extends KeyStoreSetUP {

    @InjectMocks
    JksPkcs12KeyStoreFileReader jksPkcs12KeyStoreFileReader;

    @Mock
    KeyStoreInfo keyStoreInfo;

    @Mock
    KeyStore keyStore;

    @Mock
    private Logger logger;

    private String validFileType = "PKCS12";
    private String validAliasName = "lteipsecnecus";
    private String validPassword = "C4bCzXyT";
    private String validFilePath = "src/test/resources/LTEIPSecNEcus_Sceprakeystore_1.p12";
    private String invalidAliasName = "lteipsecnecus12";
    private String invalidFilePath = "src/test/resources/LTEIPSecNEcus1_Sceprakeystore_1.p12";

    /**
     * This method is used to set up validKeyStoreInfo in the keyStoreInfo Object.
     */
    @Before
    public void setUp() {
        keyStoreInfo = getKeyStoreInfo(validFileType, validAliasName);
    }

    /**
     * Test case for checking readCertificate() method by passing valid KeyStoreInfo Object.
     */
    @Test
    public void testReadCertificate() {
        Certificate certificate = jksPkcs12KeyStoreFileReader.readCertificate(keyStoreInfo);
        assertNotNull(certificate);

        try {
            assertEquals(getCertificate(keyStoreInfo), certificate);
        } catch (KeyStoreException e) {
            logger.debug("KeyStore Exception occured ", e);
            Assert.fail("KeyStore Exception occured");
        } catch (NoSuchAlgorithmException e) {
            logger.debug("NoSuchAlgorithmException occured ", e);
            Assert.fail("NoSuchAlgorithmException occured");
        } catch (CertificateException e) {
            logger.debug("CertificateException occured ", e);
            Assert.fail("CertificateException occured");
        } catch (FileNotFoundException e) {
            logger.debug("FileNotFoundException occured ", e);
            Assert.fail("FileNotFoundException occured");
        } catch (IOException e) {
            logger.debug("IOException occured ", e);
            Assert.fail("IOException occured");
        }
    }

    /**
     * Test case for checking readCertificate method for AliasNotFoundException,by passing invalid aliasName.
     * 
     */
    @Test(expected = AliasNotFoundException.class)
    public void testReadCertificateTestWithInvalidAlias() {

        keyStoreInfo = getKeyStoreInfo(validFileType, invalidAliasName);
        Certificate certificate = jksPkcs12KeyStoreFileReader.readCertificate(keyStoreInfo);

    }

    /**
     * Test case for checking readCertificate method for InvalidKeyStoreDataException,when filepath is not valid.
     * 
     */
    @Test(expected = InvalidKeyStoreDataException.class)
    public void testReadCertificateTestWithInvalidFilePath() {
        keyStoreInfo = new KeyStoreInfo(invalidFilePath, KeyStoreType.valueOf(validFileType), validPassword, validAliasName);
        Certificate certificate = jksPkcs12KeyStoreFileReader.readCertificate(keyStoreInfo);
    }

    /**
     * Test case for checking readCertificateChain() method by passing valid KeyStoreInfo Object.
     */
    @Test
    public void testReadCertificateChain() {
        Certificate[] certificate = jksPkcs12KeyStoreFileReader.readCertificateChain(keyStoreInfo);
        assertNotNull(certificate);
        try {
            Assert.assertArrayEquals(getCertificateChain(keyStoreInfo), certificate);
        } catch (KeyStoreException e) {
            logger.debug("KeyStore Exception occured ", e);
            Assert.fail("KeyStore Exception occured");
        } catch (NoSuchAlgorithmException e) {
            logger.debug("NoSuchAlgorithmException occured ", e);
            Assert.fail("NoSuchAlgorithmException occured");
        } catch (CertificateException e) {
            logger.debug("CertificateException occured ", e);
            Assert.fail("CertificateException occured");
        } catch (FileNotFoundException e) {
            logger.debug("FileNotFoundException occured ", e);
            Assert.fail("FileNotFoundException occured");
        } catch (IOException e) {
            logger.debug("IOException occured ", e);
            Assert.fail("IOException occured");
        }

    }

    /**
     * Test case for checking readCertificateChain method for AliasNotFoundException,when aliasName is not valid.
     * 
     */
    @Test(expected = AliasNotFoundException.class)
    public void testReadCertificateChainWithInvalidAlias() {
        keyStoreInfo = getKeyStoreInfo(validFileType, invalidAliasName);
        Certificate[] certificate = jksPkcs12KeyStoreFileReader.readCertificateChain(keyStoreInfo);

    }

    /**
     * Test case for checking readPrivateKey() method.
     * 
     */
    @Test
    public void testReadPrivatekey() {
        final PrivateKey privateKey = jksPkcs12KeyStoreFileReader.readPrivateKey(keyStoreInfo);
        assertNotNull(privateKey);
    }

    /**
     * Test case for checking readPrivateKey method for AliasNotFoundException,when aliasName is not valid.
     * 
     */
    @Test(expected = AliasNotFoundException.class)
    public void testReadPrivateKeyWithInvalidAlias() {

        keyStoreInfo = new KeyStoreInfo(validFilePath, KeyStoreType.valueOf(validFileType), validPassword, invalidAliasName);
        PrivateKey privateKey = jksPkcs12KeyStoreFileReader.readPrivateKey(keyStoreInfo);
    }

    /**
     * Test case for checking readPrivateKey method for InvalidKeyStoreDataException,when password is not valid.
     * 
     */
    @Test(expected = InvalidKeyStoreDataException.class)
    public void testReadPrivateKeyWithInvalidPassword() throws KeyStoreException {

        keyStoreInfo = new KeyStoreInfo(validFilePath, KeyStoreType.valueOf(validFileType), " invalidpasswd", validAliasName);
        PrivateKey privateKey = jksPkcs12KeyStoreFileReader.readPrivateKey(keyStoreInfo);

    }

    /**
     * Test case for checking getAllAliases method for InvalidKeyStoreDataException,when password is not valid.
     * 
     */
    @Test(expected = InvalidKeyStoreDataException.class)
    public void testGetAllAliases_InvalidKeyStoreDataException() {
        keyStoreInfo = new KeyStoreInfo(validFilePath, KeyStoreType.valueOf(validFileType), " invalidpasswd", validAliasName);
        jksPkcs12KeyStoreFileReader.getAllAliases(keyStoreInfo);
    }

    /**
     * Test case for checking getAllAliases method.
     * 
     */
    @Test
    public void testGetAllAliases() {
        final List<String> aliases = jksPkcs12KeyStoreFileReader.getAllAliases(keyStoreInfo);
        assertNotNull(aliases);
        assertEquals(validAliasName, aliases.get(0));
    }
}
