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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class TrustCAChainDataTest {

    TrustCAChainData trustCAChainData;
    TrustCAChainData expectedTrustCAChainData;

    @Before
    public void setUp() {

        trustCAChainData = getTrustCAChainData();
        expectedTrustCAChainData = getTrustCAChainData();
    }

    @Test
    public void testTrustCAChainData() {

        trustCAChainData.getTrustChainId();
        trustCAChainData.getTrustProfile();
        trustCAChainData.getCAEntity();
        trustCAChainData.isChainRequired();

        trustCAChainData.hashCode();
        trustCAChainData.toString();

        assertTrue(trustCAChainData.equals(trustCAChainData));

        trustCAChainData.equals(expectedTrustCAChainData);
        trustCAChainData.equals(null);

        assertFalse(trustCAChainData.equals(getTrustProfileData()));

    }

    private TrustProfileData getTrustProfileData() {
        TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setId(1);
        trustProfileData.setName("TestProfile");
        return trustProfileData;
    }

    private TrustCAChainData getTrustCAChainData() {
        TrustCAChainData trustCAChainData = new TrustCAChainData();
        TrustCAChainId trustChainId = new TrustCAChainId();
        trustCAChainData.setChainRequired(true);
        trustCAChainData.setTrustChainId(trustChainId);
        trustCAChainData.setTrustProfile(getTrustProfileData());
        CAEntityData caEntityData = new EntityDataSetUp().createCAEntityData();
        trustCAChainData.setCAEntity(caEntityData);
        return trustCAChainData;
    }

}
