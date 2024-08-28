/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSCertificateStatusMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateStatusMapperTest {

    @InjectMocks
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Test
    public void testFromModelActive() {

        TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.ACTIVE;
        TDPSCertificateStatus tdpsCertificateStatus = tdpsCertificateStatusMapper.fromModel(tdpsCertificateStatusType);

        Assert.assertEquals(TDPSCertificateStatusType.ACTIVE + "", tdpsCertificateStatus + "");

    }

    @Test
    public void testFromModelInActive() {

        TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.INACTIVE;
        TDPSCertificateStatus tdpsCertificateStatus = tdpsCertificateStatusMapper.fromModel(tdpsCertificateStatusType);
        Assert.assertEquals(TDPSCertificateStatusType.INACTIVE + "", tdpsCertificateStatus + "");

    }

    @Test
    public void testFromModelInActiveUnknown() {

        TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.UNKNOWN;
        TDPSCertificateStatus tdpsCertificateStatus = tdpsCertificateStatusMapper.fromModel(tdpsCertificateStatusType);
        Assert.assertEquals(TDPSCertificateStatusType.UNKNOWN + "", tdpsCertificateStatus + "");
    }

    @Test
    public void testToModelActive() {

        TDPSCertificateStatus tdpsCertificateStatus = TDPSCertificateStatus.ACTIVE;
        TDPSCertificateStatusType tdpsCertificateStatusType = tdpsCertificateStatusMapper.toModel(tdpsCertificateStatus);

        Assert.assertEquals(TDPSCertificateStatus.ACTIVE + "", tdpsCertificateStatusType + "");
    }

    @Test
    public void testToModelInActive() {

        TDPSCertificateStatus tdpsCertificateStatus = TDPSCertificateStatus.INACTIVE;
        TDPSCertificateStatusType tdpsCertificateStatusType = tdpsCertificateStatusMapper.toModel(tdpsCertificateStatus);

        Assert.assertEquals(TDPSCertificateStatus.INACTIVE + "", tdpsCertificateStatusType + "");
    }

    @Test
    public void testToModelInActiveUnknown() {

        TDPSCertificateStatus tdpsCertificateStatus = TDPSCertificateStatus.UNKNOWN;
        TDPSCertificateStatusType tdpsCertificateStatusType = tdpsCertificateStatusMapper.toModel(tdpsCertificateStatus);

        Assert.assertEquals(TDPSCertificateStatus.UNKNOWN + "", tdpsCertificateStatusType + "");
    }

}
