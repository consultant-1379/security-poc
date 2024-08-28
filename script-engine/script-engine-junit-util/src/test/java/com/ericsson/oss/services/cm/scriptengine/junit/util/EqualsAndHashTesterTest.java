package com.ericsson.oss.services.cm.scriptengine.junit.util;

import org.junit.Test;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy and the other slave copy in script-engine-editor-spi.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class EqualsAndHashTesterTest {

    private final EqualsAndHashTester objUnderTest = new EqualsAndHashTester();

    private final TestObject testObject1 = new TestObject(1);
    private final TestObject testObjectIdenticalTo1 = new TestObject(1);
    private final TestObject testObject2 = new TestObject(2);

    private final TestObjectWithSeveralFieldTypes testObjectWithSeveralFieldTypes1 = new TestObjectWithSeveralFieldTypes();
    private final TestObjectWithSeveralFieldTypes testObjectWithSeveralFieldTypes2 = new TestObjectWithSeveralFieldTypes();

    @Test
    public void assertEqualsAndHashMethod_withIdenticalObjectsThrowsNoException() throws Exception {
        objUnderTest.assertEqualsAndHashMethod(testObject1, testObjectIdenticalTo1);
    }

    @Test (expected = AssertionError.class)
    public void assertEqualsAndHashMethod_withDifferentObjects_throwsAssertionError() throws Exception {
        objUnderTest.assertEqualsAndHashMethod(testObject1, testObject2);
    }

    @Test
    public void assertEqualsAndHashMethod_withOneIdenticalAndOneDifferentObjectThrowsNoException() throws Exception {
        objUnderTest.assertEqualsAndHashMethod(testObject1, testObjectIdenticalTo1, testObject2);
    }

    @Test (expected = AssertionError.class)
    public void assertEqualsAndHashMethod_withTwoIdenticalObjects_withIncompleteEqualsMethodThrowsAssertionError() throws Exception {
        final TestObjectWithIncompleteEqualsMethod testObjectWithIncompleteEqualsMethod = new TestObjectWithIncompleteEqualsMethod(1);
        objUnderTest.assertEqualsAndHashMethod(testObjectWithIncompleteEqualsMethod, testObjectWithIncompleteEqualsMethod);
    }

    @Test (expected = RuntimeException.class)
    public void assertEqualsAndHashMethod_withTwoIdenticalObjects_withIncompleteEqualsHashCodeThrowsRuntimeError() throws Exception {
        final TestObjectWithIncompleteHashCodeMethod testObjectWithIncompleteHashCodeMethod = new TestObjectWithIncompleteHashCodeMethod(1);
        objUnderTest.assertEqualsAndHashMethod(testObjectWithIncompleteHashCodeMethod, testObjectWithIncompleteHashCodeMethod);
    }

    @Test (expected = RuntimeException.class)
    public void assertEqualsAndHashMethod_withNoNonArgumentsObject_ThrowsRuntimeError() throws Exception {
        final TestObjectWithNoNoArgumentsConstructor testObjectWithNoNoArgumentsConstructor = new TestObjectWithNoNoArgumentsConstructor(1);
        objUnderTest.assertEqualsAndHashMethod(testObjectWithNoNoArgumentsConstructor, testObjectWithNoNoArgumentsConstructor);
    }

    @Test
    public void assertEqualsAndHashMethod_withObjectsWithSeveralTypes_throwsNoException() throws Exception {
        objUnderTest.assertEqualsAndHashMethod(testObjectWithSeveralFieldTypes1, testObjectWithSeveralFieldTypes1);
    }

    @Test
    public void assertEqualsAndHashMethod_withObjectsWithSeveralTypes_ignoresNonPrimitiveThatIsItThrowsNoException() throws Exception {
        testObjectWithSeveralFieldTypes1.setNonPrimitiveObject(testObject1);
        testObjectWithSeveralFieldTypes2.setNonPrimitiveObject(testObject2);
        objUnderTest.assertEqualsAndHashMethod(testObjectWithSeveralFieldTypes1, testObjectWithSeveralFieldTypes1, testObjectWithSeveralFieldTypes2);
    }
}