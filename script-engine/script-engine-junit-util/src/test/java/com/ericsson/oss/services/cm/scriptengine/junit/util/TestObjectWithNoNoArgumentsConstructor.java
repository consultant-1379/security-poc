package com.ericsson.oss.services.cm.scriptengine.junit.util;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy and the other slave copy in script-engine-editor-spi.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class TestObjectWithNoNoArgumentsConstructor {

    private int intValue = 0;

    TestObjectWithNoNoArgumentsConstructor(final int intValue) {
        this.intValue = intValue;
    }


}
