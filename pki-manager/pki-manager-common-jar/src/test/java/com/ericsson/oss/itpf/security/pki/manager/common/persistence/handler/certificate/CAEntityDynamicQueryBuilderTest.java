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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityDynamicQueryBuilderTest {

    @InjectMocks
    CAEntityDynamicQueryBuilder CAEntityDynamicQueryBuilder;

    private DNBasedCertificateIdentifier dnBasedCertificateIdentifier;

    @Before
    public void setUp() {
        dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();

    }

    @Test
    public void testWhereWithValues() {

        final StringBuilder dynamicQuery = new StringBuilder();

        dnBasedCertificateIdentifier.setSubjectDN("CN=ENMSubCA");
        dnBasedCertificateIdentifier.setIssuerDN("CN=ENMSubCA");
        dnBasedCertificateIdentifier.setCerficateSerialNumber("123");

        final Map<String, Object> expectedQueryResult = CAEntityDynamicQueryBuilder.where(dnBasedCertificateIdentifier, dynamicQuery);

        assertNotNull(expectedQueryResult);
        assertEquals(dnBasedCertificateIdentifier.getSubjectDN(), expectedQueryResult.get("subjectDN"));
        assertEquals(dnBasedCertificateIdentifier.getIssuerDN(), expectedQueryResult.get("issuerDN"));
        assertEquals(dnBasedCertificateIdentifier.getCerficateSerialNumber(), expectedQueryResult.get("serial_number"));
    }

    @Test
    public void testWhereWithEmptyValues() {

        final StringBuilder dynamicQuery = new StringBuilder();

        final Map<String, Object> expectedQueryResult = CAEntityDynamicQueryBuilder.where(dnBasedCertificateIdentifier, dynamicQuery);

        assertTrue(expectedQueryResult.isEmpty());
    }
}
