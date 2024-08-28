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
package com.ericsson.oss.itpf.security.pki.manager.rest.dto;

/**
 * This is an enum for the attributes used in filters.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
public enum AttributeType {

    ID("id");

    private final String value;

    private AttributeType(final String value) {
        this.value = value;
    }

    /**
     * @return value
     */
    public String getValue() {
        return value;
    }

}
