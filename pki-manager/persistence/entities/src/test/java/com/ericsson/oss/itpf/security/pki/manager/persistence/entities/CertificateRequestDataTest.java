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
public class CertificateRequestDataTest extends EqualsTestCase {
    @InjectMocks
    CertificateRequestData certificateRequestData;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CertificateRequestData createInstance() throws Exception {
        return getCertificateRequestData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CertificateRequestData createNotEqualInstance() throws Exception {
        return getCertificateRequestDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateRequestData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateRequestData certificateRequestData = createInstance();
        final Class<? extends Object> certificateRequestDataClass = certificateRequestData.getClass();
        final Object nullObject = null;
        final Method[] methods = certificateRequestDataClass.getMethods();
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

                    assertNotEquals(certificateRequestData, tempObject1);
                    assertNotEquals(tempObject1, certificateRequestData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CertificateRequestData getCertificateRequestData() {
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr("certificateRequest".getBytes());
        certificateRequestData.setId(1);
        certificateRequestData.setStatus(5);
        return certificateRequestData;
    }

    private CertificateRequestData getCertificateRequestDataNotEqual() {
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr("certificateRequestNew".getBytes());
        certificateRequestData.setId(2);
        certificateRequestData.setStatus(9);
        return certificateRequestData;
    }

    /**
     * This method tests toString method of CertificateRequestData class
     */
    @Test
    public void testMethods() {
        certificateRequestData = getCertificateRequestData();
        assertNotNull(certificateRequestData.toString());
    }
}
