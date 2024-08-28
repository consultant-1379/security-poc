/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1;

/**
 * This enum describes the depth of modeled objects
 *
 * @author xaschar
 *
 */
public enum MappingDepth {
    LEVEL_0("OBJECT_SUMMARY"), LEVEL_1("WITH_EMBEDDED_OBJECTS"), LEVEL_2("WITH_OBJECT_CHAIN");

    private final String name;

    private MappingDepth(final String name) {
        this.name = name;
    }

    public String getValue() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

}
