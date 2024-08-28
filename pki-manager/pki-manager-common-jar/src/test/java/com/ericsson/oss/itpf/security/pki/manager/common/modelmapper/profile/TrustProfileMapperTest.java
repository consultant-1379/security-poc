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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Test class for {@link TrustProfileMapper}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustProfileMapper.class);

    @InjectMocks
    private TrustProfileMapper trustProfileMapper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private TrustCAChainsMapper trustCAChainMapper;

    @Mock
    private ExtCAMapper extCAMapper;

    private TrustProfileData trustProfileData;
    private TrustProfile trustProfile;

    private Set<String> internalCANames;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setup() {
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfileData = trustProfileSetUpData.getTrustProfileData();
        trustProfile = trustProfileSetUpData.getTrustProfile();
        internalCANames = trustProfileSetUpData.getInternalCANames();
    }

    /**
     * Method to test toAPIModel method in positive scenario.
     */
    @Test
    public void testToAPIModel() throws Exception {

        final Iterator<TrustCAChainData> trustCAChainDataIterator = trustProfileData.getTrustCAChains().iterator();
        final Iterator<TrustCAChain> trustCAChainIterator = trustProfile.getTrustCAChains().iterator();
        if (trustCAChainDataIterator.hasNext()) {
            when(trustCAChainMapper.toAPIFromModel(trustCAChainDataIterator.next())).thenReturn(trustCAChainIterator.next());
        }

        final TrustProfile trustProfile1 = trustProfileMapper.toAPIFromModel(trustProfileData);
        assertEquals(trustProfile1.getName(), trustProfileData.getName());

    }

    /**
     * Method to test fromAPIModel method in positive scenario.
     */
    @Test
    public void testFromAPIModel() {

        final Iterator<TrustCAChainData> trustCAChainDataIterator = trustProfileData.getTrustCAChains().iterator();
        final Iterator<TrustCAChain> trustCAChainIterator = trustProfile.getTrustCAChains().iterator();
        if (trustCAChainIterator.hasNext()) {
            when(trustCAChainMapper.fromAPIToModel(trustCAChainIterator.next())).thenReturn(trustCAChainDataIterator.next());
        }

        final TrustProfileData trustProfileData1 = trustProfileMapper.fromAPIToModel(trustProfile);
        assertEquals(trustProfile.getName(), trustProfileData1.getName());

    }

    @Test
    public void testExtCAToAPIModel() throws Exception {

        final Iterator<CAEntityData> it = trustProfileData.getExternalCAs().iterator();
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("External CA 1");
        extCA.setCertificateAuthority(certificateAuthority);
        if (it.hasNext()) {
            when(extCAMapper.toAPIFromModel(it.next())).thenReturn(extCA);
        }

        final TrustProfile trustProfile1 = trustProfileMapper.toAPIFromModel(trustProfileData);
        assertEquals(trustProfile1.getExternalCAs().get(0).getCertificateAuthority().getName(), trustProfileData.getExternalCAs().iterator().next().getCertificateAuthorityData().getName());

    }
}
