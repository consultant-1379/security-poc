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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EntitySetUpData;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;

@RunWith(MockitoJUnitRunner.class)
public class EntityInfoDataTest extends EqualsTestCase {

    @InjectMocks
    EntityInfoData entityInfoData;

    @Override
    protected Object createInstance() {
        return new EntitySetUpData().getEntityForEqual();
    }

    @Override
    protected Object createNotEqualInstance() {
        return new EntitySetUpData().getEntityForNotEqual();
    }

    /**
     * Method to test equals method of {@link EntityInfoData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (!method.getName().equals("setIssuerCA") && !method.getName().equals("setCreatedDate") && !method.getName().equals("setModifiedDate")) {
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
    
    /**
     * Method to test getter method of {@link EntityInfoData}
     */
    @Test
    public void testMethods() {
    	entityInfoData = new EntitySetUpData().getEntityForEqual();
        assertNotNull(entityInfoData.getId());
        assertNotNull(entityInfoData.getStatus());
        assertNotNull(entityInfoData.getCreatedDate());
        assertNotNull(entityInfoData.getModifiedDate());
        assertNotNull(entityInfoData.toString());
    }
}
