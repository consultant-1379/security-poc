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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class RevokedCertificatesInfoTest {

    @InjectMocks
    RevokedCertificatesInfo revokedCertificatesInfo;

    private Date date;
    private String serialNumber;
    private int revocationReason;

    private RevokedCertificatesInfo revokedCertInfo;
    private RevokedCertificatesInfo revokedCertificateInfo;

    /**
     * Prepares initial data.
     */

    @Before
    public void setUpData() {

        date = new Date();
        serialNumber = "345098";
        revocationReason = 2;

        revokedCertInfo = new RevokedCertificatesInfo();
        revokedCertInfo.setInvalidityDate(date);
        revokedCertInfo.setRevocationDate(date);
        revokedCertInfo.setRevocationReason(revocationReason);
        revokedCertInfo.setSerialNumber(serialNumber);

        revokedCertificateInfo = new RevokedCertificatesInfo();
        revokedCertificateInfo.setInvalidityDate(date);
        revokedCertificateInfo.setRevocationDate(date);
        revokedCertificateInfo.setRevocationReason(revocationReason);
        revokedCertificateInfo.setSerialNumber(serialNumber);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo#hashCode()}.
     */
    @Test
    public void testHashCode() {

        assertNotNull(revokedCertInfo.hashCode());
        assertNotNull(revokedCertInfo.toString());
        assertTrue(revokedCertInfo.equals(revokedCertificateInfo));

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo#getRevocationDate()}.
     */
    @Test
    public void testRevocationDate() {

        revokedCertificatesInfo.setRevocationDate(date);
        assertEquals(revokedCertificatesInfo.getRevocationDate(), date);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo#getSerialNumber()}.
     */
    @Test
    public void testSerialNumber() {

        revokedCertificatesInfo.setSerialNumber(serialNumber);
        assertEquals(revokedCertificatesInfo.getSerialNumber(), serialNumber);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo#getRevocationReason()}.
     */
    @Test
    public void testRevocationReason() {

        revokedCertificatesInfo.setRevocationReason(revocationReason);
        assertEquals(revokedCertificatesInfo.getRevocationReason(), revocationReason);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo#getInvalidityDate()}.
     */
    @Test
    public void testInvalidityDate() {

        revokedCertificatesInfo.setInvalidityDate(date);
        assertEquals(revokedCertificatesInfo.getInvalidityDate(), date);
    }

}
