/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;

@RunWith(MockitoJUnitRunner.class)
public class CRLDataTest extends EqualsTestCase {

    @InjectMocks
    CRLData crlData;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CRLData createInstance() throws Exception {
        return getCRLData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CRLData createNotEqualInstance() throws Exception {
        return getCRLDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CRLData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CRLData crlData = createInstance();
        final Class<? extends Object> crlDataClass = crlData.getClass();
        final Object nullObject = null;
        final Method[] methods = crlDataClass.getMethods();
        Object tempObject1 = null;
        Object tempObject2 = null;
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()
                        && !method.getParameterTypes()[0].isInterface()) {

                    tempObject1 = createNotEqualInstance();
                    tempObject2 = createNotEqualInstance();

                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);

                    assertNotEquals(crlData, tempObject1);
                    assertNotEquals(tempObject1, crlData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CRLData getCRLData() {
        final CRLData crlData = new CRLData();
        crlData.setCrl("crl".getBytes());
        crlData.setId(3);
        return crlData;
    }

    private CRLData getCRLDataNotEqual() {
        final CRLData crlData = new CRLData();
        crlData.setCrl("crlNew".getBytes());
        crlData.setId(6);
        return crlData;
    }

    /**
     * This method tests getter and toString methods of CRLData class
     */
    @Test
    public void testMethods() {
        crlData = getCRLData();
        assertNotNull(crlData.getId());
        assertNotNull(crlData.getCrl());
        assertNotNull(crlData.toString());
    }
}
