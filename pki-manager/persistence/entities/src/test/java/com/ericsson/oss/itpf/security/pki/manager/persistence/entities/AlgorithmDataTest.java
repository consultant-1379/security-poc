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
import java.util.HashSet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.AlgorithmDataSetUp;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmDataTest extends EqualsTestCase {
    @InjectMocks
    AlgorithmData algorithmData;

    AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected AlgorithmData createInstance() throws Exception {
        return algorithmDataSetUp.getSupportedSignatureAlgorithm();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected AlgorithmData createNotEqualInstance() throws Exception {
        return algorithmDataSetUp.getSupportedKeyGenerationAlgorithm();
    }

    /**
     * Method to test equals method of {@link AlgorithmData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final AlgorithmData algorithmData = createInstance();
        final Class<? extends Object> algorithmDataClass = algorithmData.getClass();
        final Object nullObject = null;
        final Method[] methods = algorithmDataClass.getMethods();
        Object tempObject1 = null;
        Object tempObject2 = null;
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {

                    tempObject1 = createNotEqualInstance();
                    tempObject2 = createNotEqualInstance();

                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);

                    assertNotEquals(algorithmData, tempObject1);
                    assertNotEquals(tempObject1, algorithmData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    /**
     * This method tests getters,setters and toString methods of AlgorithmData class
     */
    @Test
    public void testMethods() {
        algorithmData.onCreate();
        algorithmData.onUpdate();
        algorithmData.setName("test");
        algorithmData.setId(1);
        algorithmData.setOid("1.2.3.4.5");
        algorithmData.setType(1);
        algorithmData.setKeySize(1);
        algorithmData.setCategories(new HashSet<Integer>(1));

        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(algorithmData.getCreatedDate());
        assertNotNull(algorithmData.getModifiedDate());
        assertNotNull(algorithmData.toString());
        assertNotNull(algorithmData.getName());
        assertNotNull(algorithmData.getId());
        assertNotNull(algorithmData.getOid());
        assertNotNull(algorithmData.getType());
        assertNotNull(algorithmData.getKeySize());
        assertNotNull(algorithmData.getCategories());
    }
}
