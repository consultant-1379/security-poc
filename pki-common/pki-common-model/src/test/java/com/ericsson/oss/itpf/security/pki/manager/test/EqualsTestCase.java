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
package com.ericsson.oss.itpf.security.pki.manager.test;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import junit.framework.AssertionFailedError;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.test.setup.CommonConstants;

/**
 * This class acts as base for Junits to test two objects in different scenarios {@link EqualsTestCase}
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class EqualsTestCase {

    @Mock
    private Logger logger;

    private Object eq1;
    private Object eq2;
    private Object eq3;
    private Object neq;
    private static final int NUM_ITERATIONS = 20;
    private final List<String> primitiveTypesList = Arrays.asList("byte", "short", "int", "long", "float", "double", "boolean", "char");

    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other.
     * @throws DatatypeConfigurationException
     * @throws Exception
     */
    protected abstract Object createInstance() throws ParseException, DatatypeConfigurationException;

    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other, but not to the objects returned from {@link #createInstance()
     *         createInstance}.
     * @throws Exception
     */
    protected abstract Object createNotEqualInstance() throws ParseException, DatatypeConfigurationException;

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
            throw new IllegalArgumentException(ex.getMessage(), ex);
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
     * Tests object with setting each field to null.
     * 
     * @throws Exception
     */
    @Test
    public void testWithEachFieldNull() throws Exception {
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
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
     * Tests object with changing each field with different value.
     */
    @Test
    public void testWithEachFieldChange() throws Exception {
        final Class tClass = eq1.getClass();

        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();

        for (final Method method : methods) {
            if (method.getName().matches(CommonConstants.SET_ID)) {
                continue;
            }
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (!method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (primitiveTypesList.contains(method.getParameterTypes()[0].getName())) {
                        Object getterMethodvalue = null;
                        Object newSetterMethodvalue = null;
                        if (!method.getParameterTypes()[0].getName().equals(CommonConstants.BOOLEAN_STRING)) {
                            final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                            getterMethodvalue = getterMethod.invoke(tempObject2);
                        } else {
                            for (final Method tempGetterMethod : methods) {
                                final String casesensitiveName = tempGetterMethod.getName().toLowerCase();
                                final String setMethod = method.getName().toLowerCase();
                                if (setMethod.replaceFirst(CommonConstants.SET, "is").contains(casesensitiveName) || setMethod.replaceFirst("is", "").contains(casesensitiveName)) {
                                    try {
                                        final Method getterMethod = tClass.getMethod(tempGetterMethod.getName());
                                        getterMethodvalue = getterMethod.invoke(tempObject2);
                                    } catch (NoSuchMethodException noSuchMethodException) {
                                        logger.debug("Invalid method name ", noSuchMethodException);
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
     * Tests object with shuffling list objects.
     */
    @Test
    public void testWithShuffledLists() throws Exception {
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (method.getParameterTypes()[0].getName().contains(CommonConstants.LIST) && !method.getParameterTypes()[0].isEnum()) {

                    Object getterMethodvalue = null;
                    Object newSetterMethodvalue = null;
                    try {
                        final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                        getterMethodvalue = getterMethod.invoke(tempObject2);
                    } catch (Exception exception) {
                        logger.debug("Exception in shuffled list ", exception);
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
     * Tests object with setting each list field to empty.
     */
    @Test
    public void testWithEmptyList() throws Exception {
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (method.getParameterTypes()[0].getName().contains(CommonConstants.LIST) && !method.getParameterTypes()[0].isEnum()) {

                    Object getterMethodvalue = null;
                    Object newSetterMethodvalue = null;
                    try {
                        final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                        getterMethodvalue = getterMethod.invoke(tempObject2);
                    } catch (Exception exception) {
                        logger.debug("Exception occured ", exception);
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
        case CommonConstants.BOOLEAN_STRING:
            final boolean actualValue = (boolean) value;
            if (!actualValue) {
                return (Object) true;
            } else {
                return (Object) false;
            }
        case CommonConstants.INT_STRING:
        case CommonConstants.FLOAT_STRING:
        case CommonConstants.LONG_STRING:
        case CommonConstants.SHORT_STRING:
        case CommonConstants.DOUBLE_STRING:
            return (Object) 999;
        case CommonConstants.BYTE_STRING:
            return (Object) 999;
        case CommonConstants.CHAR_STRING:
            return (Object) '~';
        default:
            return null;
        }
    }
}
