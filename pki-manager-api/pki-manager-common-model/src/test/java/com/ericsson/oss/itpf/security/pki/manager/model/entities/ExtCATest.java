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
package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;

import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.ExtCASetUpData;

/**
 * This class is used to run Junits for ExtCA objects in different scenarios
 */
public class ExtCATest extends EqualsTestCase {

    private static final String SET_STRING = "set";

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() {
        try {
            return new ExtCASetUpData().getExtCAForEqual();
        } catch (final ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() {
        return new ExtCASetUpData().getExtCAForNotEqual();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEachFieldNull()
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(SET_STRING)) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
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
