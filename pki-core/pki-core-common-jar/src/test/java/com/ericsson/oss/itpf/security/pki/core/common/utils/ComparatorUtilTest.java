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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class ComparatorUtilTest {

    @InjectMocks
    private ComparatorUtil comparatorUtil;

    private CertificateData certificateData1;

    private CertificateData certificateData2;

    @Before
    public void setUp() {

    }

    /**
     * Test method to get the positive value
     */
    @Test
    public void testCompare_ReturnsPositiveValue() {

        setValueToReturnPositiveInt();
        final int result = comparatorUtil.compare(certificateData1, certificateData2);

        assertNotNull(result);
        assertEquals(1, result);

    }

    /**
     * Test method to get the negative value
     */
    @Test
    public void testCompare_ReturnsNegativeValue() {

        setValueToReturnNegativeInt();
        final int result = comparatorUtil.compare(certificateData1, certificateData2);

        assertNotNull(result);
        assertEquals(-1, result);

    }

    /**
     * Test method to get the zero.
     */
    @Test
    public void testCompare_ReturnsZero() {

        setValueToReturnZero();
        final int result = comparatorUtil.compare(certificateData1, certificateData2);

        assertNotNull(result);
        assertEquals(0, result);

    }

    private void setValueToReturnPositiveInt() {

        certificateData1 = new CertificateData();
        certificateData1.setId(2);

        certificateData2 = new CertificateData();
        certificateData2.setId(1);
    }

    private void setValueToReturnNegativeInt() {

        certificateData1 = new CertificateData();
        certificateData1.setId(1);

        certificateData2 = new CertificateData();
        certificateData2.setId(2);
    }

    private void setValueToReturnZero() {

        certificateData1 = new CertificateData();
        certificateData1.setId(0);

        certificateData2 = new CertificateData();
        certificateData2.setId(0);
    }
}
