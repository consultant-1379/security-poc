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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.modelmapper;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateAuthorityModelMapper.class);

    @InjectMocks
    CertificateAuthorityModelMapper caEntityMapper;

    @Mock
    PersistenceManager persistenceManager;

    CertificateAuthority certificateAuthority;
    CertificateAuthorityData certificateAuthorityData;

    EntityInfo entityInfo;
    EntityInfoData entityInfoData;
    
    @Mock
    private SystemRecorder systemRecorder;

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        certificateAuthority = entitiesSetUpData.getCertificateAuthority();
        certificateAuthorityData = entitiesSetUpData.getCertificateAuthorityData();
        entityInfo = entitiesSetUpData.getEntityInfo();
        entityInfoData = entitiesSetUpData.getEntityInfoData();
    }

    @Test
    public void toAPIFromModel() throws Exception {

        final CertificateAuthority certificateAuthority = caEntityMapper.toAPIModel(certificateAuthorityData);

        assertEquals(certificateAuthorityData.getId(), certificateAuthority.getId());
        assertEquals(certificateAuthorityData.getName(), certificateAuthority.getName());
        assertEquals(certificateAuthorityData.getSubjectDN(), certificateAuthority.getSubject().toASN1String());
        assertEquals(certificateAuthorityData.getSubjectAltName(), JsonUtil.getJsonFromObject(certificateAuthority.getSubjectAltName()));
        assertEquals(certificateAuthorityData.isRootCA(), certificateAuthority.isRootCA());
    }

    @Test
    public void testfromAPIToModel() {

        final CertificateAuthorityData certificateAuthorityData = caEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);

        assertEquals(certificateAuthority.getId(), certificateAuthorityData.getId());
        assertEquals(certificateAuthority.getName(), certificateAuthorityData.getName());
        assertEquals(certificateAuthority.getSubject().toASN1String(), certificateAuthorityData.getSubjectDN());
        assertEquals(JsonUtil.getJsonFromObject(certificateAuthority.getSubjectAltName()), certificateAuthorityData.getSubjectAltName());
        assertEquals(certificateAuthority.isRootCA(), certificateAuthorityData.isRootCA());
    }

}
