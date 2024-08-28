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

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;

/*
 * This class is used to build the validateItem object.
 */
public class ValidateItemBuilder {

    private ItemType itemType;
    private OperationType operationType;
    private Object item;
    private boolean skipOptionalTests = false;

    public ValidateItemBuilder setItemType(final ItemType itemType) {
        this.itemType = itemType;
        return this;
    }

    public ValidateItemBuilder setOperationType(final OperationType operationType) {
        this.operationType = operationType;
        return this;
    }

    public ValidateItemBuilder setItem(final Object item) {
        this.item = item;
        return this;
    }

    public ValidateItemBuilder setSkipOptionalTests(final boolean skipOptionalTests) {
        this.skipOptionalTests = skipOptionalTests;
        return this;
    }

    /**
     * This method will build the validateItem object.
     * 
     * @return ValidateItem
     */
    public ValidateItem build() {
        final ValidateItem validateItem = new ValidateItem();

        validateItem.setItemType(itemType);
        validateItem.setOperationType(operationType);
        validateItem.setItem(item);
        validateItem.setSkipOptionalTests(skipOptionalTests);

        return validateItem;
    }
}
