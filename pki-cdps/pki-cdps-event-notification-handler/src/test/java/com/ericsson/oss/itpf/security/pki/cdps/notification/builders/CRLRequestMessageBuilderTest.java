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
package com.ericsson.oss.itpf.security.pki.cdps.notification.builders;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLRequestMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test CRLRequestMessageBuilder functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLRequestMessageBuilderTest extends SetUpData {

    @InjectMocks
    CRLRequestMessageBuilder crlRequestMessageBuilder;

    private List<CACertificateInfo> caCertInfoList;

    private CRLRequestMessageBuilder crlRequestMessageBuilderReturn;

    private CRLRequestMessage crlRequestMessageReturn;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertInfoList = prepareCACertificateInfoList();

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLRequestMessageBuilder#caCertificateInfos(java.util.List)} .
     */
    @Test
    public void testCaCertificateInfos() {

        crlRequestMessageBuilderReturn = crlRequestMessageBuilder.caCertificateInfos(caCertInfoList);

        assertNotNull(crlRequestMessageBuilderReturn);
        assertEquals(crlRequestMessageBuilder, crlRequestMessageBuilderReturn);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLRequestMessageBuilder#build()} .
     */
    @Test
    public void testBuild() {

        crlRequestMessageBuilder.caCertificateInfos(caCertInfoList);

        crlRequestMessageReturn = crlRequestMessageBuilder.build();

        assertNotNull(crlRequestMessageReturn);
        assertEquals(caCertInfoList.get(0).getCaName(), crlRequestMessageReturn.getCaCertificateInfoList().get(0).getCaName());
        assertEquals(caCertInfoList.get(0).getCertificateSerialNumber(), crlRequestMessageReturn.getCaCertificateInfoList().get(0).getCertificateSerialNumber());
    }

}
