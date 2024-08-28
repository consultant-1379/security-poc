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
package com.ericsson.oss.itpf.security.pki.common.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.setUp.KeyStoreSetUP;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;

/**
 * This class is a junit test class for CertificateUtility class.
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateUtilityTest extends KeyStoreSetUP {

    @InjectMocks
    private CertificateUtility certificateUtility;

    @Mock
    KeyStoreInfo keyStoreInfo;

    @Mock
    private Logger logger;

    private static String keyStoreType = "PKCS12";
    private static String aliasName = "lteipsecnecus";
    private static KeyStore keyStore;

    /**
     * This method is used to set up validKeyStoreInfo in the keyStoreInfo Object.
     */
    @Before
    public void setUp() {
        keyStoreInfo = getKeyStoreInfo(keyStoreType, aliasName);
        try {
            keyStore = loadKeyStore(keyStoreInfo);
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
     * Test case for checking getCertificateFromByteArray() method.
     * 
     * @throws KeyStoreException
     *             ,CertificateEncodingException
     */
    @Test
    public void testGetCertificateFromByteArray() {
        try {
            final Certificate certificate = keyStore.getCertificate(aliasName);
            final byte[] certificateByteArray = certificate.getEncoded();
            X509Certificate x509certificate = CertificateUtility.getCertificateFromByteArray(certificateByteArray);
            assertNotNull(x509certificate);
            byte[] decodedCertificate = x509certificate.getEncoded();
            assertArrayEquals(decodedCertificate, certificateByteArray);
        } catch (KeyStoreException e) {
            logger.debug("KeyStore Exception occured ", e);
            Assert.fail("KeyStore Exception occured");
        } catch (CertificateEncodingException e) {
            logger.debug("CertificateEncodingException occured ", e);
            Assert.fail("CertificateEncodingException occured");
        }
    }

    /**
     * Test case for checking getCertificateFromByteArray() method for CertificateConversionException thrown when invalid byte array is passed.
     * 
     * @throws KeyStoreException
     *             ,CertificateEncodingException
     */
    @Test(expected = CertificateConversionException.class)
    public void testGetCertificateFromByteArrayException() {
        try {
            final Certificate certificate = keyStore.getCertificate(aliasName);
            final byte[] certificateByteArray = certificate.getEncoded();
            byte[] invalidByte = "InvalidByte".getBytes();
            byte[] finalInvalidByte = new byte[certificateByteArray.length + invalidByte.length];
            CertificateUtility.getCertificateFromByteArray(finalInvalidByte);
        } catch (KeyStoreException e) {
            logger.debug("KeyStore Exception occured ", e);
            Assert.fail("KeyStore Exception occured");
        } catch (CertificateEncodingException e) {
            logger.debug("CertificateEncodingException occured ", e);
            Assert.fail("CertificateEncodingException occured");
        }

    }

}
