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
package com.ericsson.oss.itpf.security.pki.manager.model.profiles;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.TrustProfileSetUpData;

/**
 * This class is used to run Junits for Trust Profile objects in different scenarios
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileTest extends EqualsTestCase {
    private static final String SET_INTERNAL_CAENTITY = "setInternalCAEntities";
    private static final String SET_EXTERNAL_CAENTITY = "setExternalCAs";
    private static final String SET_STRING = "set";
    private static final String LIST_STRING = "List";

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() throws DatatypeConfigurationException {
        return new TrustProfileSetUpData().getTrustProfileDataForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() throws DatatypeConfigurationException {
        return new TrustProfileSetUpData().getTrustProfileDataForNotEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEachFieldNull()
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, DatatypeConfigurationException {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(SET_STRING)) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (!method.getName().equals(SET_INTERNAL_CAENTITY) && !method.getName().equals(SET_EXTERNAL_CAENTITY)) {
                        method.invoke(tempObject2, nullObject);
                        method.invoke(tempObject1, nullObject);
                        assertNotEquals(eq1, tempObject1);
                        assertNotEquals(tempObject1, eq1);
                        assertEquals(tempObject1, tempObject2);
                        tempObject1 = createInstance();
                        tempObject2 = createInstance();
                    }
                }
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEmptyList()
     */
    @Override
    @Test
    public void testWithEmptyList() throws Exception {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();

        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(SET_STRING)) {
                if (method.getParameterTypes()[0].getName().contains(LIST_STRING) && !method.getParameterTypes()[0].isEnum() && !method.getName().startsWith(SET_INTERNAL_CAENTITY)
                        && !method.getName().startsWith(SET_EXTERNAL_CAENTITY)) {
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
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }
}
