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
public class TrustCAChainIdTest {

    TrustCAChainId trustCAChainId;
    TrustCAChainId expectedTrustCAChainId;

    @Before
    public void setUp() {
        trustCAChainId = getTrustCAChainID();
        expectedTrustCAChainId = getTrustCAChainID();
    }

    @Test
    public void testTrustCAChainIdTest() {
        trustCAChainId.getCaEntityData();
        trustCAChainId.getTrustProfileData();
        trustCAChainId.hashCode();
        trustCAChainId.toString();
        trustCAChainId.equals(null);

        assertTrue(trustCAChainId.equals(trustCAChainId));

        trustCAChainId.equals(expectedTrustCAChainId);

        assertFalse(trustCAChainId.equals(new TrustProfileData()));

    }

    @Test
    public void testTrustCAChainIdTestNotEquals() {

        TrustCAChainId trustCAChainId = getTrustCAChainID();
        TrustCAChainId expectedTrustCAChainId = getTrustCAChainID();
        CAEntityData caEntityData = trustCAChainId.getCaEntityData();
        caEntityData.setId(1023);
        trustCAChainId.setCaEntityData(caEntityData);

        assertFalse(trustCAChainId.equals(expectedTrustCAChainId));

        trustCAChainId.setCaEntityData(null);

        assertFalse(trustCAChainId.equals(expectedTrustCAChainId));

    }

    private TrustProfileData getTrustProfileData() {
        TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setId(1);
        trustProfileData.setName("TestProfile");
        return trustProfileData;
    }

    private TrustCAChainId getTrustCAChainID() {
        TrustCAChainId trustChainId = new TrustCAChainId();
        trustChainId.setTrustProfileData(getTrustProfileData());
        CAEntityData caEntityData = new EntityDataSetUp().createCAEntityData();
        trustChainId.setCaEntityData(caEntityData);
        return trustChainId;
    }

}
