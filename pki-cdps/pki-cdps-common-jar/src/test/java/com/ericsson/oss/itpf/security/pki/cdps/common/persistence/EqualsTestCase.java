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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.util.*;

import junit.framework.AssertionFailedError;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;

/**
 * This class used to test CDPSEntityData functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class EqualsTestCase {

    private CDPSEntityData cdpsEntityData;
    private CDPSEntityData cdpsEnttyData;
    private CDPSEntityData cdpsEntyData;
    private CDPSEntityData cdpsEntityDataNotEqual;
    private static final int NUM_ITERATIONS = 20;
    final private List<String> primitiveTypesList = Arrays.asList("byte", "short", "int", "long", "float", "double", "boolean", "char");

    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other.
     * @throws Exception
     */
    protected abstract CDPSEntityData createCDPSEntityDataInstance();

    /**
     * Creates and returns an instance of the class under test.
     * 
     * @return a new instance of the class under test; each object returned from this method should compare equal to each other, but not to the objects returned from
     *         {@link #createCDPSEntityDataInstance() createInstance}.
     * @throws Exception
     */
    protected abstract CDPSEntityData createNotEqualCDPSEntityDataInstance();

    /**
     * Sets up the test fixture.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        cdpsEntityData = createCDPSEntityDataInstance();
        cdpsEnttyData = createCDPSEntityDataInstance();
        cdpsEntyData = createCDPSEntityDataInstance();
        cdpsEntityDataNotEqual = createNotEqualCDPSEntityDataInstance();
        // We want these assertions to yield errors, not failures.
        try {
            assertNotNull("createInstance() returned null", cdpsEntityData);
            assertNotNull("2nd createInstance() returned null", cdpsEnttyData);
            assertNotNull("3rd createInstance() returned null", cdpsEntyData);
            assertNotNull("createNotEqualInstance() returned null", cdpsEntityDataNotEqual);
            assertNotSame(cdpsEntityData, cdpsEnttyData);
            assertNotSame(cdpsEntityData, cdpsEntyData);
            assertNotSame(cdpsEntityData, cdpsEntityDataNotEqual);
            assertNotSame(cdpsEnttyData, cdpsEntyData);
            assertNotSame(cdpsEnttyData, cdpsEntityDataNotEqual);
            assertNotSame(cdpsEntyData, cdpsEntityDataNotEqual);
            assertEquals("1st and 2nd equal instances of different classes", cdpsEntityData.getClass(), cdpsEnttyData.getClass());
            assertEquals("1st and 3rd equal instances of different classes", cdpsEntityData.getClass(), cdpsEntyData.getClass());
            assertEquals("1st equal instance and not-equal instance of different classes", cdpsEntityData.getClass(), cdpsEntityDataNotEqual.getClass());
        } catch (AssertionFailedError ex) {
            throw new IllegalArgumentException(ex.getMessage());
        }
    }

    /**
     * Tests whether <code>equals</code> holds up against a new <code>Object</code> (should always be <code>false</code>).
     */
    @Test
    public final void testEqualsAgainstNewObject() {
        final CDPSEntityData cdpsEntityDataTest = new CDPSEntityData();
        assertNotEquals(cdpsEntityData, cdpsEntityDataTest);
        assertNotEquals(cdpsEnttyData, cdpsEntityDataTest);
        assertNotEquals(cdpsEntyData, cdpsEntityDataTest);
        assertNotEquals(cdpsEntityDataNotEqual, cdpsEntityDataTest);
    }

    /**
     * Tests whether <code>equals</code> holds up against <code>null</code>.
     */
    @Test
    public final void testEqualsAgainstNull() {
        Assert.assertNotEquals("null vs. 1st", cdpsEntityData, null);
        Assert.assertNotEquals("null vs. 2nd", cdpsEnttyData, null);
        Assert.assertNotEquals("null vs. 3rd", cdpsEntyData, null);
        Assert.assertNotEquals("null vs. not-equal", cdpsEntityDataNotEqual, null);
    }

    /**
     * Tests whether <code>equals</code> holds up against objects that should not compare equal.
     */
    @Test
    public final void testEqualsAgainstUnequalObjects() {
        Assert.assertNotEquals("1st vs. not-equal", cdpsEntityData, cdpsEntityDataNotEqual);
        Assert.assertNotEquals("2nd vs. not-equal", cdpsEnttyData, cdpsEntityDataNotEqual);
        Assert.assertNotEquals("3rd vs. not-equal", cdpsEntyData, cdpsEntityDataNotEqual);
        Assert.assertNotEquals("not-equal vs. 1st", cdpsEntityDataNotEqual, cdpsEntityData);
        Assert.assertNotEquals("not-equal vs. 2nd", cdpsEntityDataNotEqual, cdpsEnttyData);
        Assert.assertNotEquals("not-equal vs. 3rd", cdpsEntityDataNotEqual, cdpsEntyData);
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
        assertEquals("1st equal instance", cdpsEntityData, cdpsEntityData);
        assertEquals("2nd equal instance", cdpsEnttyData, cdpsEnttyData);
        assertEquals("3rd equal instance", cdpsEntyData, cdpsEntyData);
        assertEquals("not-equal instance", cdpsEntityDataNotEqual, cdpsEntityDataNotEqual);
    }

    /**
     * Tests whether <code>equals</code> is <em>symmetric</em> and <em>transitive</em>.
     */
    @Test
    public final void testEqualsIsSymmetricAndTransitive() {
        assertEquals("1st vs. 2nd", cdpsEntityData, cdpsEnttyData);
        assertEquals("2nd vs. 1st", cdpsEnttyData, cdpsEntityData);
        assertEquals("1st vs. 3rd", cdpsEntityData, cdpsEntyData);
        assertEquals("3rd vs. 1st", cdpsEntyData, cdpsEntityData);
        assertEquals("2nd vs. 3rd", cdpsEnttyData, cdpsEntyData);
        assertEquals("3rd vs. 2nd", cdpsEntyData, cdpsEnttyData);
    }

    @Test
    public void testWithEachFieldNull() throws Exception {
        final Class tClass = cdpsEntityData.getClass();
        final CDPSEntityData nullObject = null;
        final Method[] methods = tClass.getMethods();
        CDPSEntityData tempObject1 = createCDPSEntityDataInstance();
        CDPSEntityData tempObject2 = createCDPSEntityDataInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);
                    assertNotEquals(cdpsEntityData, tempObject1);
                    assertNotEquals(tempObject1, cdpsEntityData);
                    assertNotEquals(tempObject1, cdpsEntityDataNotEqual);
                    assertNotEquals(cdpsEntityDataNotEqual, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createCDPSEntityDataInstance();
                    tempObject2 = createCDPSEntityDataInstance();
                }
            }
        }
    }

    @Test
    public void testWithEachFieldChange() throws Exception {
        final Class tClass = cdpsEntityData.getClass();

        final Method[] methods = tClass.getMethods();
        CDPSEntityData tempObject1 = createCDPSEntityDataInstance();
        CDPSEntityData tempObject2 = createCDPSEntityDataInstance();

        for (final Method method : methods) {
            if (method.getName().matches("setId")) {
                continue;
            }
            if (method.getName().startsWith("set")) {
                if (!method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (primitiveTypesList.contains(method.getParameterTypes()[0].getName())) {
                        Object getterMethodvalue = null;
                        Object newSetterMethodvalue = null;
                        if (!method.getParameterTypes()[0].getName().equals("boolean")) {
                            final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                            getterMethodvalue = getterMethod.invoke(tempObject2);
                        } else {
                            for (final Method tempGetterMethod : methods) {
                                final String casesensitiveName = tempGetterMethod.getName().toLowerCase();
                                final String setMethod = method.getName().toLowerCase();
                                if (setMethod.replaceFirst("set", "is").contains(casesensitiveName) || setMethod.replaceFirst("is", "").contains(casesensitiveName)) {
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

                        assertNotEquals(cdpsEntityData, tempObject1);
                        assertNotEquals(tempObject1, cdpsEntityData);
                        assertNotEquals(tempObject1, cdpsEntityDataNotEqual);
                        assertNotEquals(cdpsEntityDataNotEqual, tempObject1);
                        assertEquals(tempObject1, tempObject2);
                        tempObject1 = createCDPSEntityDataInstance();
                        tempObject2 = createCDPSEntityDataInstance();
                    }
                }
            }
        }
    }

    @Test
    public void testWithShuffledLists() throws Exception {
        final Class tClass = cdpsEntityData.getClass();
        final Method[] methods = tClass.getMethods();
        CDPSEntityData tempObject1 = createCDPSEntityDataInstance();
        CDPSEntityData tempObject2 = createCDPSEntityDataInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains("List") && !method.getParameterTypes()[0].isEnum()) {

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
                    assertEquals(cdpsEntityData, tempObject1);
                    assertEquals(tempObject1, cdpsEntityData);
                    assertNotEquals(tempObject1, cdpsEntityDataNotEqual);
                    assertNotEquals(cdpsEntityDataNotEqual, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createCDPSEntityDataInstance();
                    tempObject2 = createCDPSEntityDataInstance();
                }
            }
        }
    }

    @Test
    public void testWithEmptyList() throws Exception {
        final Class tClass = cdpsEntityData.getClass();
        final Method[] methods = tClass.getMethods();
        CDPSEntityData tempObject1 = createCDPSEntityDataInstance();
        CDPSEntityData tempObject2 = createCDPSEntityDataInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains("List") && !method.getParameterTypes()[0].isEnum()) {

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
                    assertNotEquals(cdpsEntityData, tempObject1);
                    assertNotEquals(tempObject1, cdpsEntityData);
                    assertNotEquals(tempObject1, cdpsEntityDataNotEqual);
                    assertNotEquals(cdpsEntityDataNotEqual, tempObject1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createCDPSEntityDataInstance();
                    tempObject2 = createCDPSEntityDataInstance();
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
        case "boolean":
            final boolean actualValue = (boolean) value;
            if (!actualValue) {
                return (Object) true;
            } else {
                return (Object) false;
            }
        case "int":
        case "short":
        case "long":
        case "float":
        case "double":
            return (Object) 999;
        case "byte":
            return (Object) 999;
        case "char":
            return (Object) '~';
        default:
            return null;
        }
    }

    /**
     * Tests the <code>hashCode</code> contract.
     */
    @Test
    public final void testHashCodeContract() {
        assertEquals("1st vs. 2nd", cdpsEntityData.hashCode(), cdpsEnttyData.hashCode());
        assertEquals("1st vs. 3rd", cdpsEntityData.hashCode(), cdpsEntyData.hashCode());
        assertEquals("2nd vs. 3rd", cdpsEnttyData.hashCode(), cdpsEntyData.hashCode());
    }

    /**
     * Tests the consistency of <code>hashCode</code>.
     */
    @Test
    public final void testHashCodeIsConsistentAcrossInvocations() {
        final int eq1Hash = cdpsEntityData.hashCode();
        final int eq2Hash = cdpsEnttyData.hashCode();
        final int eq3Hash = cdpsEntyData.hashCode();
        final int neqHash = cdpsEntityDataNotEqual.hashCode();
        for (int i = 0; i < NUM_ITERATIONS; ++i) {
            assertEquals("1st equal instance", eq1Hash, cdpsEntityData.hashCode());
            assertEquals("2nd equal instance", eq2Hash, cdpsEnttyData.hashCode());
            assertEquals("3rd equal instance", eq3Hash, cdpsEntyData.hashCode());
            assertEquals("not-equal instance", neqHash, cdpsEntityDataNotEqual.hashCode());
        }
    }
}
