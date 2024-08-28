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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ItemTypeTest {

    /**
     * Method to test Enum ItemType methods in positive scenario
     */
    @Test
    public void testItemTypeValues() {
        Assert.assertNotNull(ItemType.valueOf("CERTIFICATE_PROFILE"));
        Assert.assertNotNull(ItemType.fromValue("caentity"));
        Assert.assertNotNull(ItemType.values());

    }

    /**
     * Method to test Enum ItemType method in Negative scenario
     */
    @Test(expected = IllegalArgumentException.class)
    public void testItemTypeValuesWithInvalidValue() {
        ItemType.fromValue("test");
    }
}
