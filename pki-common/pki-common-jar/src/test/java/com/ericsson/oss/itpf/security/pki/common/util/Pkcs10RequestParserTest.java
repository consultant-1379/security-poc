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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.*;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.setUp.PKCS10CertificationRequestSetUP;

/**
 * This class is a junit test class for Pkcs10RequestParser class.
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class Pkcs10RequestParserTest extends PKCS10CertificationRequestSetUP {

    @InjectMocks
    Pkcs10RequestParser pkcs10RequestParser;
    @Mock
    PKCS10CertificationRequest pkcs10RequestParser1;
    @Mock
    ASN1Set derStr;
    @Mock
    ASN1Encodable asn1;
    @Mock
    private Logger logger;

    PKCS10CertificationRequest pkcs10CertificationRequest;
    String challengePassword = "2ER13SA32SAD2G3";
    X500Name csrSubject = new X500Name("CN=ERBS_1");

    /**
     * This method is used to generate valid CSR.
     * 
     */
    @Before
    public void setUp() {

        try {
            pkcs10CertificationRequest = generateCSR("RSA", "SHA256WithRSA", csrSubject);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException e) {
            logger.debug("Failed to generate CSR ", e);
            Assert.fail("Failed to generate CSR");
        }
    }

    /**
     * Test case for checking getPassword() method.
     * 
     */
    @Test
    public void testGetPassword() {

        String password = pkcs10RequestParser.getPassword(pkcs10CertificationRequest);
        assertNotNull(password);
        assertEquals(challengePassword, password);

    }

    /**
     * Test case for checking getRequestDN() method.
     * 
     */
    @Test
    public void testGetRequestDN() {
        X500Name requestDN = pkcs10RequestParser.getRequestDN(pkcs10CertificationRequest);
        assertNotNull(requestDN);
        assertEquals(csrSubject, requestDN);

    }

    /**
     * Test case for checking getPassword() method for returning null when attributes are null.
     * 
     */
    @Test
    public void testGetPasswordforAttributeNullCheck() {
        Mockito.when(pkcs10RequestParser1.getAttributes()).thenReturn(null);
        String password = pkcs10RequestParser.getPassword(pkcs10RequestParser1);
        assertEquals(null, password);
    }

    /**
     * Test case for checking getPassword() method for IllegalArgumentException.
     * 
     */
    @Test(expected = IllegalArgumentException.class)
    public void testGetPasswordforIllegealAttributeException() {
        try {
            pkcs10CertificationRequest = generateCSRWithInvalidAttribute("RSA", "SHA256WithRSA", csrSubject);
        } catch (InvalidKeyException e) {
            logger.debug("InvalidKey Exception occured ", e);
            Assert.fail("InvalidKey Exception occured");
        } catch (NoSuchAlgorithmException e) {
            logger.debug("NoSuchAlgorithmException occured ", e);
            Assert.fail("NoSuchAlgorithmException occured");
        } catch (SignatureException e) {
            logger.debug("SignatureException occured ", e);
            Assert.fail("SignatureException occured");
        } catch (IOException e) {
            logger.debug("IOException occured ", e);
            Assert.fail("IOException occured");
        }
        pkcs10RequestParser.getPassword(pkcs10CertificationRequest);
    }

}
