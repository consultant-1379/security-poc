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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.assertNotNull;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class will test EntityData
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileDataTest {

    @Test
    public void testTrustProfileData() {

        TrustProfileData trustProfileData = new TrustProfileData();

        Set<TrustCAChainData> trustCAChains = new HashSet<TrustCAChainData>();

        Set<CAEntityData> externalCAs = new HashSet<CAEntityData>();

        trustProfileData.setTrustCAChains(trustCAChains);
        trustProfileData.setExternalCAs(externalCAs);

        trustProfileData.getTrustCAChains();
        trustProfileData.getExternalCAs();

        assertNotNull(trustProfileData.toString());

    }

}
