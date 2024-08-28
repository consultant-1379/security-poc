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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSAcknowledgementEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

/**
 * 
 * @author tcsasma
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class TDPSAcknowledgementEventBuilderTest {

    @InjectMocks
    TDPSAcknowledgementEventBuilder tdpsAcknowledgementEventBuilder;

    @Mock
    TDPSErrorInfo tdpsErroInfo;

    @Test
    public void testBuild() {
        tdpsAcknowledgementEventBuilder.build();

    }

    @Test
    public void testTDPSOperationType(){
        tdpsAcknowledgementEventBuilder.tDPSOperationType(TDPSOperationType.PUBLISH);
    }

    @Test
    public void testTDPSErrorInfo() {
        tdpsAcknowledgementEventBuilder.tDPSErrorInfo(tdpsErroInfo);
    }

    @Test
    public void testTDPSResponseType(){
        tdpsAcknowledgementEventBuilder.tDPSResponseType(TDPSResponseType.SUCCESS);
    }

    @Test
    public void testTDPSCertificateInfoList(){
        List<TDPSCertificateInfo> certificateInfoList = new ArrayList<TDPSCertificateInfo>();
        tdpsAcknowledgementEventBuilder.tDPSCertificateInfoList(certificateInfoList);
    }
}
