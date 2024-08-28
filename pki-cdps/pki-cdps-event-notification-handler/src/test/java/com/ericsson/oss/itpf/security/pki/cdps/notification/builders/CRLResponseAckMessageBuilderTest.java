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
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSResponseType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test CRLResponseAckMessageBuilder functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLResponseAckMessageBuilderTest extends SetUpData {

    @InjectMocks
    CRLResponseAckMessageBuilder crlResponseAckMessageBuilder;

    private List<CACertificateInfo> caCertInfoList;

    private CRLResponseAckMessageBuilder crlResponseAckMessageBuilderReturn;

    private CDPSOperationType cdpsOperationType;

    private CDPSResponseType cdpsResponseType;

    private CRLResponseAckMessage crlResponseAckMessageReturn;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertInfoList = prepareCACertificateInfoList();

        cdpsOperationType = CDPSOperationType.PUBLISH;

        cdpsResponseType = CDPSResponseType.SUCCESS;

        crlResponseAckMessageBuilder.caCertificateInfos(caCertInfoList);

        crlResponseAckMessageBuilder.cdpsOperationType(cdpsOperationType);

        crlResponseAckMessageBuilder.cdpsResponseType(cdpsResponseType);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder#caCertificateInfos(java.util.List)} .
     */
    @Test
    public void testCaCertificateInfos() {

        crlResponseAckMessageBuilderReturn = crlResponseAckMessageBuilder.caCertificateInfos(caCertInfoList);

        assertNotNull(crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder, crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder.caCertificateInfos(caCertInfoList), crlResponseAckMessageBuilderReturn.caCertificateInfos(caCertInfoList));

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder#cdpsOperationType(com.ericsson.oss.itpf.security.pki.ra.cdps.edt.CDPSOperationType)} .
     */
    @Test
    public void testCdpsOperationType() {

        crlResponseAckMessageBuilderReturn = crlResponseAckMessageBuilder.cdpsOperationType(cdpsOperationType);

        assertNotNull(crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder, crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder.cdpsOperationType(cdpsOperationType), crlResponseAckMessageBuilderReturn.cdpsOperationType(cdpsOperationType));

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder#cdpsResponseType(com.ericsson.oss.itpf.security.pki.ra.cdps.edt.CDPSResponseType)} .
     */
    @Test
    public void testCdpsResponseType() {

        crlResponseAckMessageBuilderReturn = crlResponseAckMessageBuilder.cdpsResponseType(cdpsResponseType);

        assertNotNull(crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder, crlResponseAckMessageBuilderReturn);
        assertEquals(crlResponseAckMessageBuilder.cdpsResponseType(cdpsResponseType), crlResponseAckMessageBuilderReturn.cdpsResponseType(cdpsResponseType));

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder#build()} .
     */
    @Test
    public void testBuild() {

        crlResponseAckMessageReturn = crlResponseAckMessageBuilder.build();

        assertNotNull(crlResponseAckMessageReturn);
        assertEquals(caCertInfoList.get(0).getCaName(), crlResponseAckMessageReturn.getCaCertificateInfoList().get(0).getCaName());
        assertEquals(cdpsOperationType, crlResponseAckMessageReturn.getCdpsOperationType());

    }

}
