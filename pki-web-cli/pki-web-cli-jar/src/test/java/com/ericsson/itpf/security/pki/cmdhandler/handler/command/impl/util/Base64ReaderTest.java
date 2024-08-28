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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;

@RunWith(MockitoJUnitRunner.class)
public class Base64ReaderTest {

    Base64Reader base64Reader;

    @Before
    public void setUp() {
        final String filePath = "src/test/resources/CSR.csr";
        base64Reader = new Base64Reader(Constants.EMPTY_STRING, filePath, Constants.EMPTY_STRING, filePath, "secure");
    }

    @Test
    public void testGetPrivateKey() {
        try {
            base64Reader.getPrivateKey();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void testGetCertificate() {
        base64Reader.getCertificate(Constants.EMPTY_STRING);
    }

    @Test
    public void testGetCRL() {
        try {
            base64Reader.getCRL();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}
