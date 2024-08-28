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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CACertificateIdentifierBuilder;

@RunWith(MockitoJUnitRunner.class)
public class CACertificateIdentifierBuilderTest {

    @InjectMocks
    CACertificateIdentifierBuilder caCertificateIdentifierBuilder;

    private String caName;

    private String cerficateSerialNumber;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caName = "TestingCACertificate";
        cerficateSerialNumber = "123456";
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CACertificateIdentifierBuilder#caName(java.lang.String)}.
     */
    @Test
    public void testCaName() {

        CACertificateIdentifierBuilder cACertificateIdentifierBuilder = caCertificateIdentifierBuilder.caName(caName);

        assertNotNull(cACertificateIdentifierBuilder);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CACertificateIdentifierBuilder#cerficateSerialNumber(java.lang.String)}.
     */
    @Test
    public void testCerficateSerialNumber() {

        CACertificateIdentifierBuilder cACertificateIdentifierBuilder = caCertificateIdentifierBuilder.cerficateSerialNumber(cerficateSerialNumber);

        assertNotNull(cACertificateIdentifierBuilder);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CACertificateIdentifierBuilder#build()}.
     */
    @Test
    public void testBuild() {

        caCertificateIdentifierBuilder.caName(caName);
        caCertificateIdentifierBuilder.cerficateSerialNumber(cerficateSerialNumber);

        CACertificateIdentifier cACertificateIdentifier = caCertificateIdentifierBuilder.build();

        assertNotNull(cACertificateIdentifier);
        assertEquals(caName, cACertificateIdentifier.getCaName());
        assertEquals(cerficateSerialNumber, cACertificateIdentifier.getCerficateSerialNumber());
    }

}
