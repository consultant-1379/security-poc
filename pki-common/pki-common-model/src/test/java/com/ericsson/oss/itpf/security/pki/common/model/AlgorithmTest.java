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
package com.ericsson.oss.itpf.security.pki.common.model;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.AlgorithmSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CommonConstants;

/**
 * This class is used to run Junits for Algorithm objects in different scenarios
 */

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmTest extends EqualsTestCase {

    private static final String SIGNATURE_ALGORITHM_NAME = "SHA512withRSA";
    private static final int SIGNATURE_ALGORITHM_KEYSIZE = 4096;
    private static final String SIGNATURE_ALGORITHM_OID = "1.2.840.113549.1.1.13";

    private static final String ASYMMETRIC_KEY_ALGORITHM_NAME = "RSA";

    private static final int ASYMMETRIC_KEY_ALGORITHM_KEYSIZE = 512;
    private static final String ASYMMETRIC_KEY_ALGORITHM_OID = "10.11.1.1.13";

    @InjectMocks
    Algorithm algorithm;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    public Object createInstance() {
        final List<AlgorithmCategory> algorithmCategories = new ArrayList<AlgorithmCategory>();
        algorithmCategories.add(AlgorithmCategory.KEY_IDENTIFIER);

        return (new AlgorithmSetUpData()).name(SIGNATURE_ALGORITHM_NAME).keySize(SIGNATURE_ALGORITHM_KEYSIZE).oid(SIGNATURE_ALGORITHM_OID).type(AlgorithmType.SIGNATURE_ALGORITHM)
                .algorithmCategories(algorithmCategories).build();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    public Object createNotEqualInstance() {

        final List<AlgorithmCategory> algorithmCategories = new ArrayList<AlgorithmCategory>();
        algorithmCategories.add(AlgorithmCategory.OTHER);

        return (new AlgorithmSetUpData()).name(ASYMMETRIC_KEY_ALGORITHM_NAME).keySize(ASYMMETRIC_KEY_ALGORITHM_KEYSIZE).oid(ASYMMETRIC_KEY_ALGORITHM_OID).supported(true)
                .type(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM).algorithmCategories(algorithmCategories).build();

    }

    /**
     * Method will test the Algorithm object with each field as Null
     * 
     * @return Nothing
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
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (!method.getName().equals(CommonConstants.SET_KEY_SIZE)) {
                        method.invoke(tempObject2, nullObject);
                        method.invoke(tempObject1, nullObject);
                        assertEquals(tempObject1, tempObject2);
                        tempObject1 = createInstance();
                        tempObject2 = createInstance();
                    }
                }
            }
        }
    }
}
