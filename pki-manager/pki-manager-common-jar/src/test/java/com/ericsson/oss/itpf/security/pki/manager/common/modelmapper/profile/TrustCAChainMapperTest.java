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
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.data.TrustCAChainSetupData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustCAChainData;

@RunWith(MockitoJUnitRunner.class)
public class TrustCAChainMapperTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustProfileMapper.class);

    @InjectMocks
    private TrustCAChainsMapper trustCAChainsMapper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private CAEntityMapper caEntityMapper;

    @Mock
    private CRLGenerationInfoMapper cRLGenerationInfoMapper;

    private final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";

    private TrustCAChain trustCAChain;
    private TrustCAChainData trustCAChainData;
    private List<CrlGenerationInfo> crlGenerationInfo = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setup() {
        final TrustCAChainSetupData trustCAChainSetupData = new TrustCAChainSetupData();
        trustCAChain = trustCAChainSetupData.getTrustCAChain();
        trustCAChainData = trustCAChainSetupData.getTrustCAChainData();
    }

    /**
     * Method to test toAPIModel method in positive scenario.
     */

    @Test
    public void testToAPIModel() throws Exception {

        try {
            Mockito.when(cRLGenerationInfoMapper.toAPIFromModel(Mockito.anySet())).thenReturn(crlGenerationInfo);
        } catch (InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            fail(e.getMessage());
        }
        final TrustCAChain trustCAChain1 = trustCAChainsMapper.toAPIFromModel(trustCAChainData);

        assertEquals(trustCAChain1, trustCAChain);

    }

    /**
     * Method to test fromAPIModel method in positive scenario.
     */
    @Test
    public void testFromAPIModel() {

        when(persistenceManager.findEntityByName(CAEntityData.class, trustCAChain.getInternalCA().getCertificateAuthority().getName(), NAME_PATH_IN_CA)).thenReturn(trustCAChainData.getCAEntity());
        final TrustCAChainData trustCAChainData1 = trustCAChainsMapper.fromAPIToModel(trustCAChain);

        assertEquals(trustCAChainData, trustCAChainData1);
    }

    /**
     * Method to test fromAPIModel method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testFromAPIModelException() {

        when(persistenceManager.findEntityByName(CAEntityData.class, trustCAChain.getInternalCA().getCertificateAuthority().getName(), NAME_PATH_IN_CA)).thenThrow(new PersistenceException());
        trustCAChainsMapper.fromAPIToModel(trustCAChain);
    }

}
