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
package com.ericsson.oss.itpf.security.pki.manager.persistence;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.util.*;

import junit.framework.AssertionFailedError;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class acts as base for Junits to test two objects in different scenarios {@link EqualsTestCase}
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class EqualsTestCase {
    
    private final List<String> primitiveTypesList = Arrays.asList("byte", "short", "int", "long", "float", "double", "boolean", "char");

    private static final String SET = "set";
    private static final String SET_ID = "setId";
    private static final String LIST = "List";
    private static final String BOOLEAN_STRING = "boolean";
    private static final String INT_STRING = "int";
    private static final String FLOAT_STRING = "float";
    private static final String LONG_STRING = "long";
    private static final String SHORT_STRING = "short";
    private static final String DOUBLE_STRING = "double";
    private static final String BYTE_STRING = "byte";
    private static final String CHAR_STRING = "char";
    private static final int NUM_ITERATIONS = 20;
    
    private Object eq1;
    private Object eq2;
    private Object eq3;
    private Object neq;
        
    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other.
     * @throws Exception
     */
    protected abstract Object createInstance() throws Exception;

    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other, but not to the objects returned from {@link #createInstance()
     *         createInstance}.
     * @throws Exception
     */
    protected abstract Object createNotEqualInstance() throws Exception;

    /**
     * Sets up the test fixture.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        eq1 = createInstance();
        eq2 = createInstance();
        eq3 = createInstance();
        neq = createNotEqualInstance();
        try {
            assertNotNull("createInstance() returned null", eq1);
            assertNotNull("2nd createInstance() returned null", eq2);
            assertNotNull("3rd createInstance() returned null", eq3);
            assertNotNull("createNotEqualInstance() returned null", neq);
            assertNotSame(eq1, eq2);
            assertNotSame(eq1, eq3);
            assertNotSame(eq1, neq);
            assertNotSame(eq2, eq3);
            assertNotSame(eq2, neq);
            assertNotSame(eq3, neq);
            assertEquals("1st and 2nd equal instances of different classes", eq1.getClass(), eq2.getClass());
            assertEquals("1st and 3rd equal instances of different classes", eq1.getClass(), eq3.getClass());
            assertEquals("1st equal instance and not-equal instance of different classes", eq1.getClass(), neq.getClass());
        } catch (AssertionFailedError ex) {
            throw new IllegalArgumentException(ex.getMessage());
        }
    }

    /**
     * Tests whether <code>equals</code> holds up against a new <code>Object</code> (should always be <code>false</code>).
     */
    @Test
    public final void testEqualsAgainstNewObject() {
        final Object o = new Object();
        assertNotEquals(eq1, o);
        assertNotEquals(eq2, o);
        assertNotEquals(eq3, o);
        assertNotEquals(neq, o);
    }

    /**
     * Tests whether <code>equals</code> holds up against <code>null</code>.
     */
    @Test
    public final void testEqualsAgainstNull() {
        Assert.assertNotEquals("null vs. 1st", eq1, null);
        Assert.assertNotEquals("null vs. 2nd", eq2, null);
        Assert.assertNotEquals("null vs. 3rd", eq3, null);
        Assert.assertNotEquals("null vs. not-equal", neq, null);
    }

    /**
     * Tests whether <code>equals</code> holds up against objects that should not compare equal.
     */
    @Test
    public final void testEqualsAgainstUnequalObjects() {
        Assert.assertNotEquals("1st vs. not-equal", eq1, neq);
        Assert.assertNotEquals("2nd vs. not-equal", eq2, neq);
        Assert.assertNotEquals("3rd vs. not-equal", eq3, neq);
        Assert.assertNotEquals("not-equal vs. 1st", neq, eq1);
        Assert.assertNotEquals("not-equal vs. 2nd", neq, eq2);
        Assert.assertNotEquals("not-equal vs. 3rd", neq, eq3);
    }

    /**
     * Tests whether <code>equals</code> is <em>consistent</em>.
     */
    @Test
    public final void testEqualsIsConsistentAcrossInvocations() {
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            testEqualsAgainstNewObject();
            testEqualsAgainstNull();
            testEqualsAgainstUnequalObjects();
            testEqualsIsReflexive();
            testEqualsIsSymmetricAndTransitive();
        }
    }

    /**
     * Tests whether <code>equals</code> is <em>reflexive</em>.
     */
    @Test
    public final void testEqualsIsReflexive() {
        assertEquals("1st equal instance", eq1, eq1);
        assertEquals("2nd equal instance", eq2, eq2);
        assertEquals("3rd equal instance", eq3, eq3);
        assertEquals("not-equal instance", neq, neq);
    }

    /**
     * Tests whether <code>equals</code> is <em>symmetric</em> and <em>transitive</em>.
     */
    @Test
    public final void testEqualsIsSymmetricAndTransitive() {
        assertEquals("1st vs. 2nd", eq1, eq2);
        assertEquals("2nd vs. 1st", eq2, eq1);
        assertEquals("1st vs. 3rd", eq1, eq3);
        assertEquals("3rd vs. 1st", eq3, eq1);
        assertEquals("2nd vs. 3rd", eq2, eq3);
        assertEquals("3rd vs. 2nd", eq3, eq2);
    }

    /**
     * Tests Object with setting each field to null.
     */
    @Test
    public void testWithEachFieldNull() throws Exception {
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);
                    assertNotEquals(eq1, tempObject1);
                    assertNotEquals(tempObject1, eq1);
                    assertNotEquals(tempObject1, neq);
                    assertNotEquals(neq, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }

    /**
     * Tests Object with changing each field to different value.
     */
    @Test
    public void testWithEachFieldChange() throws Exception {
        final Class tClass = eq1.getClass();

        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();

        for (final Method method : methods) {
            if (method.getName().matches(SET_ID)) {
                continue;
            }
            if (method.getName().startsWith(SET)) {
                if (!method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (primitiveTypesList.contains(method.getParameterTypes()[0].getName())) {
                        Object getterMethodvalue = null;
                        Object newSetterMethodvalue = null;
                        if (!method.getParameterTypes()[0].getName().equals(BOOLEAN_STRING)) {
                            final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                            getterMethodvalue = getterMethod.invoke(tempObject2);
                        } else {
                            for (final Method tempGetterMethod : methods) {
                                final String casesensitiveName = tempGetterMethod.getName().toLowerCase();
                                final String setMethod = method.getName().toLowerCase();
                                if (setMethod.replaceFirst(SET, "is").contains(casesensitiveName) || setMethod.replaceFirst("is", "").contains(casesensitiveName)) {
                                    try {
                                        final Method getterMethod = tClass.getMethod(tempGetterMethod.getName());
                                        getterMethodvalue = getterMethod.invoke(tempObject2);
                                    } catch (NoSuchMethodException noSuchMethodException) {
                                        continue;
                                    }
                                }
                            }
                        }
                        if (getterMethodvalue != null) {
                            newSetterMethodvalue = getChangedValue(getterMethodvalue, method.getParameterTypes()[0].getName());
                        }

                        method.invoke(tempObject2, newSetterMethodvalue);
                        method.invoke(tempObject1, newSetterMethodvalue);

                        assertNotEquals(eq1, tempObject1);
                        assertNotEquals(tempObject1, eq1);
                        assertNotEquals(tempObject1, neq);
                        assertNotEquals(neq, tempObject1);
                        assertEquals(tempObject1, tempObject2);
                        tempObject1 = createInstance();
                        tempObject2 = createInstance();
                    }
                }
            }
        }
    }

    /**
     * Tests Object with shuffling each list field.
     */
    @Test
    public void testWithShuffledLists() throws Exception {
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(SET)) {
                if (method.getParameterTypes()[0].getName().contains(LIST) && !method.getParameterTypes()[0].isEnum()) {

                    Object getterMethodvalue = null;
                    Object newSetterMethodvalue = null;
                    try {
                        final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                        getterMethodvalue = getterMethod.invoke(tempObject2);
                    } catch (Exception exception) {
                        continue;
                    }
                    if (getterMethodvalue != null) {
                        newSetterMethodvalue = getShuffledList(getterMethodvalue);
                    }
                    method.invoke(tempObject2, newSetterMethodvalue);
                    method.invoke(tempObject1, newSetterMethodvalue);
                    assertEquals(eq1, tempObject1);
                    assertEquals(tempObject1, eq1);
                    assertNotEquals(tempObject1, neq);
                    assertNotEquals(neq, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }

    /**
     * Tests Object with setting each list field to empty.
     */
    @Test
    public void testWithEmptyList() throws Exception {
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(SET)) {
                if (method.getParameterTypes()[0].getName().contains(LIST) && !method.getParameterTypes()[0].isEnum()) {

                    Object getterMethodvalue = null;
                    Object newSetterMethodvalue = null;
                    try {
                        final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                        getterMethodvalue = getterMethod.invoke(tempObject2);
                    } catch (Exception exception) {
                        continue;
                    }
                    if (getterMethodvalue != null) {
                        newSetterMethodvalue = new ArrayList();
                    }
                    method.invoke(tempObject2, newSetterMethodvalue);
                    method.invoke(tempObject1, newSetterMethodvalue);
                    assertNotEquals(eq1, tempObject1);
                    assertNotEquals(tempObject1, eq1);
                    assertNotEquals(tempObject1, neq);
                    assertNotEquals(neq, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }

    private Object getShuffledList(final Object listValue) {
        final List shuffledList = (List) listValue;
        final List actualList = new ArrayList(shuffledList);
        if (shuffledList.size() > 1) {
            for (;;) {
                Collections.shuffle(shuffledList);
                if (!actualList.equals(shuffledList)) {
                    break;
                }
            }
        }
        return shuffledList;
    }

    private Object getChangedValue(final Object value, final String type) {
        switch (type) {
        case BOOLEAN_STRING:
            final boolean actualValue = (boolean) value;
            if (!actualValue) {
                {
                    return (Object) true;
                }
            } else {
                return (Object) false;
            }
        case INT_STRING:
        case FLOAT_STRING:
        case LONG_STRING:
        case SHORT_STRING:
        case DOUBLE_STRING:
            return (Object) 999;
        case BYTE_STRING:
            return (Object) 999;
        case CHAR_STRING:
            return (Object) '~';
        default:
            return null;
        }
    }

    /**
     * Tests the consistency of <code>hashCode</code>.
     */
    @Test
    public final void testHashCodeIsConsistentAcrossInvocations() {
        final int eq1Hash = eq1.hashCode();
        final int eq2Hash = eq2.hashCode();
        final int eq3Hash = eq3.hashCode();
        final int neqHash = neq.hashCode();
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            assertEquals("1st equal instance", eq1Hash, eq1.hashCode());
            assertEquals("2nd equal instance", eq2Hash, eq2.hashCode());
            assertEquals("3rd equal instance", eq3Hash, eq3.hashCode());
            assertEquals("not-equal instance", neqHash, neq.hashCode());
        }
    }
}
