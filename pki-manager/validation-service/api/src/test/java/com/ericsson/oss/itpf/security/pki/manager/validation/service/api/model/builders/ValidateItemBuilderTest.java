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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.builders;

import junit.framework.Assert;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class ValidateItemBuilderTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ValidateItemBuilder.class);

    @InjectMocks
    ValidateItemBuilder validateItemBuilder;

    /**
     * Method to test validate item.
     */
    @Test
    public void testValidateItem() {
        validateItemBuilder.setItem(new Object());
        validateItemBuilder.setItemType(ItemType.CERTIFICATE_PROFILE);
        validateItemBuilder.setOperationType(OperationType.CREATE);
        final ValidateItem validateItem = validateItemBuilder.build();
        Assert.assertNotNull(validateItem);
    }
}
