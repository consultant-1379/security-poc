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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CRLData;

/**
 * To test method of {@link CRLData}
 * @author tcsviku
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLDataTest extends EqualsTestCase {

    @InjectMocks
    CRLData crlData;

    /*
     * (non-Javadoc)
     *
     * @see  com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase#createInstance()
     * 
     */
    @Override
    protected CRLData createInstance() {
        return new CRLSetUpData().getCRLDataForEqual();
    }

    /*
     * (non-Javadoc)
     *
     * @see  com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase#createNotEqualInstance()
     * 
     */
    @Override
    protected CRLData createNotEqualInstance() {
        return new CRLSetUpData().getCRLDataForNotEqual();
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
    
    /**
     * Method to test getter method of {@link CRLData}
     */
    @Test
    public void testMethods() {
        crlData = new CRLSetUpData().getCRLDataForEqual();
        assertNotNull(crlData.getId());
        assertNotNull(crlData.getCrl());
        assertNotNull(crlData.toString());
    }
}
