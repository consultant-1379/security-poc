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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.CAEntityManager;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityManagementServiceBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAEntityManagementServiceBean.class);

    @InjectMocks
    CAEntityManagementServiceBean cAEntityManagementServiceBean;

    @Mock
    CAEntityManager cAEntitiesManager;

    CertificateAuthority certificateAuthority = new CertificateAuthority();

    @Before
    public void setup() {

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(1);
        certificateAuthority.setName("ENMRootCA");
    }

    @Test
    public void testCreateEntity() {

        when(cAEntitiesManager.createCA(certificateAuthority)).thenReturn(certificateAuthority);

        assertEquals(certificateAuthority, cAEntityManagementServiceBean.createCA(certificateAuthority));
    }

    @Test(expected = NullPointerException.class)
    public void testCreateNull() {

        cAEntityManagementServiceBean.createCA(null);
    }

    @Test
    public void testUpdateEntity() {

        when(cAEntitiesManager.updateCA(certificateAuthority)).thenReturn(certificateAuthority);

        assertEquals(certificateAuthority, cAEntityManagementServiceBean.updateCA(certificateAuthority));
    }

    @Test(expected = NullPointerException.class)
    public void testUpdateNull() {

        cAEntityManagementServiceBean.updateCA(null);
    }

    @Test
    public void testDeteleEntity() {

        cAEntityManagementServiceBean.deleteCA(certificateAuthority);
        verify(cAEntitiesManager).deleteCA(certificateAuthority);
    }

    @Test(expected = NullPointerException.class)
    public void testDeleteEntityNull() {

        cAEntityManagementServiceBean.deleteCA(null);
    }

}
