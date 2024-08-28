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
package com.ericsson.oss.itpf.security.pki.cdps.notification.events;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.local.service.api.CRLDistributionPointLocalService;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CRLDistributionPointLocalServiceWrapperTest {

    @InjectMocks
    CRLDistributionPointLocalServiceWrapper CRLDistributionPointLocalServiceWrapper;

    @Mock
    CRLDistributionPointLocalService crlDistributionPointLocalService;

    SetUpData setUpData;
    List<CRLInfo> crlInfoList = new ArrayList<CRLInfo>();
    List<CACertificateInfo> caCertificateInfos = new ArrayList<CACertificateInfo>();

    @Before
    public void setUpData() {

        setUpData = new SetUpData();
        crlInfoList.add(setUpData.prepareCRLInfo());
        caCertificateInfos.add(setUpData.prepareCACertificateInfo());

    }

    @Test
    public void testPublishCRL() {

        CRLDistributionPointLocalServiceWrapper.publishCRL(crlInfoList);
    }

    @Test
    public void testUnPublishCRL() {

        CRLDistributionPointLocalServiceWrapper.unPublishCRL(caCertificateInfos);
    }

}
