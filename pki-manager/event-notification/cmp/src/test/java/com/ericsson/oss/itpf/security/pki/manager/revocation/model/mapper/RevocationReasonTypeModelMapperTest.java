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
package com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;

@RunWith(MockitoJUnitRunner.class)
public class RevocationReasonTypeModelMapperTest {

    @InjectMocks
    RevocationReasonTypeModelMapper revocationReasonTypeModelMapper;

    @Mock
    RevocationRequest revocationServiceRequestXMLData;

    @Test
    public void testFromModel() {
        Mockito.when(revocationServiceRequestXMLData.getRevocationReason()).thenReturn("SUPERSEDED");
        revocationReasonTypeModelMapper.fromModel(revocationServiceRequestXMLData);
        Assert.assertEquals("SUPERSEDED", revocationServiceRequestXMLData.getRevocationReason());
    }

    @Test
    public void testFromModelforUnspecified() {
        Mockito.when(revocationServiceRequestXMLData.getRevocationReason()).thenReturn("UNSPECIFIED");
        revocationReasonTypeModelMapper.fromModel(revocationServiceRequestXMLData);
        Assert.assertEquals("UNSPECIFIED", revocationServiceRequestXMLData.getRevocationReason());
    }
}
