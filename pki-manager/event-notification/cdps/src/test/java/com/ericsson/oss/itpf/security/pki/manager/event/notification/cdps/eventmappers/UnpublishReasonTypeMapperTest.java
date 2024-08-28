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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.UnpublishReasonTypeMapper;

@RunWith(MockitoJUnitRunner.class)
public class UnpublishReasonTypeMapperTest {

    @InjectMocks
    UnpublishReasonTypeMapper unpublishReasonTypeMapper;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void fromModel_REVOKED_CA_CERTIFICATE() {
        UnpublishReasonType unpublishReasonType = unpublishReasonTypeMapper.fromModel(CRLUnpublishType.REVOKED_CA_CERTIFICATE);
        Assert.assertNotNull(unpublishReasonType);
    }

    @Test
    public void fromModel_EXPIRED_CA_CERTIFICATE() {
        UnpublishReasonType unpublishReasonType = unpublishReasonTypeMapper.fromModel(CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Assert.assertNotNull(unpublishReasonType);
    }

    @Test
    public void forModel_Default() {
        UnpublishReasonType unpublishReasonType = unpublishReasonTypeMapper.fromModel(CRLUnpublishType.USER_INVOKED_REQUEST);
        Assert.assertNull(unpublishReasonType);
    }

}
