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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;

/**
 * ValidateItem contains details of the object which is to be validated.
 */
public class ValidateItem {

    private ItemType itemType;
    private OperationType operationType;
    private Object item;
    private boolean skipOptionalTests = false;

    /**
     * @return the itemType
     */
    public ItemType getItemType() {
        return itemType;
    }

    /**
     * @param itemType
     *            the itemType to set
     */
    public void setItemType(final ItemType itemType) {
        this.itemType = itemType;
    }

    /**
     * @return the operationType
     */
    public OperationType getOperationType() {
        return operationType;
    }

    /**
     * @param operationType
     *            the operationType to set
     */
    public void setOperationType(final OperationType operationType) {
        this.operationType = operationType;
    }

    /**
     * @return the item
     */
    public Object getItem() {
        return item;
    }

    /**
     * @param item
     *            the item to set
     */
    public void setItem(final Object item) {
        this.item = item;
    }

    /**
     * @return the skipOptionalTests
     */
    public boolean isSkipOptionalTests() {
        return skipOptionalTests;
    }

    /**
     * @param skipOptionalTests
     *            the skipOptionalTests to set
     */
    public void setSkipOptionalTests(final boolean skipOptionalTests) {
        this.skipOptionalTests = skipOptionalTests;
    }

}
