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
/**
 * @author tcsvenp
 *
 */
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;

import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CertificateSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CommonConstants;

/**
 * This class is used to run Junits for Certificate objects in different scenarios
 */
public class CertificateTest extends EqualsTestCase {

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() throws ParseException {
        return new CertificateSetUpData().getCertificateForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() throws ParseException {
        return new CertificateSetUpData().getCertificateForNotEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEachFieldNull()
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, ParseException {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    if (!method.getName().equals(CommonConstants.SET_X509_CERTIFICATE) && !method.getName().equals(CommonConstants.SET_GENERATED_FROM_CSR)
                            && !method.getName().startsWith(CommonConstants.SET_ISSUER)) {
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

}