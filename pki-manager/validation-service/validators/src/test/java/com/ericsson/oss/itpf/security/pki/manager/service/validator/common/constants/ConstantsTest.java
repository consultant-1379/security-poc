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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ConstantsTest {
    @InjectMocks
    Constants constants;

    /**
     * This method tests all the constant values
     */
    @Test
    public void testAllConstanValues() {
        Assert.assertEquals(constants.NAME_PATH, "name");

        Assert.assertEquals(constants.NAME_PATH, "name");
        Assert.assertEquals(constants.OCCURED_IN_VALIDATING, " Occured in Validating!");
        Assert.assertEquals(constants.ENTITY_CATEGORY, " in entity category!");
        Assert.assertEquals(constants.GIVEN_KEY_GENERATION_ALGORITHM, "Given key generation algorithm ");
        Assert.assertEquals(constants.GIVEN_ALGORITHM, "Given signature algorithm ");
        Assert.assertEquals(constants.GIVEN_EXTERNAL_CA, "Given External CA(s) ");
        Assert.assertEquals(constants.GIVEN_INTERNAL_CA, "Given Internal CA(s) ");
        Assert.assertEquals(constants.KEY_USAGE, "For key usage, ");
    }
}
