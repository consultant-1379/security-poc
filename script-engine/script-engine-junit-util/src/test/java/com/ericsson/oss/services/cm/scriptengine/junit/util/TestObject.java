package com.ericsson.oss.services.cm.scriptengine.junit.util;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy and the other slave copy in script-engine-editor-spi.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class TestObject {

    private int intValue = 0;

    TestObject() {
    }

    TestObject(final int intValue) {
        this.intValue = intValue;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + intValue;
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof TestObject)) {
            return false;
        }
        final TestObject other = (TestObject) obj;
        if (intValue != other.intValue) {
            return false;
        }
        return true;
    }

}
