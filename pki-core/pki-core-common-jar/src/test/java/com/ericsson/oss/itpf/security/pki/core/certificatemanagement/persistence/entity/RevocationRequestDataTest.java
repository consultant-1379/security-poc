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

import static org.junit.Assert.*;

import java.lang.reflect.Method;

import javax.inject.Inject;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;

/**
 * To test method of {@link RevocationRequestData}
 * @author tcsviku
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class RevocationRequestDataTest extends EqualsTestCase {

    @InjectMocks
    RevocationRequestSetUpData revocationRequestSetUpData;
    
    @Inject
    RevocationRequestData revocationRequestData;

    /*
     * (non-Javadoc)
     *
     * @see  com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase#createInstance()
     * 
     */
    @Override
    protected Object createInstance() {
        return new RevocationRequestSetUpData().getRevocationRequestForEqual();
    }

    /*
     * (non-Javadoc)
     *
     * @see  com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase#createNotEqualInstance()
     * 
     */
    @Override
    protected Object createNotEqualInstance() {
        return revocationRequestSetUpData.getRevocationRequestForNotEqual();
    }

    /**
     * Method to test equals method of {@link RevocationRequestData}
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
                   
                        method.invoke(tempObject2, nullObject);
                        method.invoke(tempObject1, nullObject);
                        tempObject1 = createInstance();
                        tempObject2 = createInstance();
                    
                }
            }
        }
    }
    
    /**
     * Method to test getter method of {@link RevocationRequestData}
     */
    @Test
    public void testMethods() {
        revocationRequestData = new RevocationRequestSetUpData().getRevocationRequestForEqual();

        assertNotNull(revocationRequestData.getId());
        assertNotNull(revocationRequestData.getCaEntity());
        assertNotNull(revocationRequestData.getCertificatesToRevoke());
        assertNotNull(revocationRequestData.getEntity());
        assertNotNull(revocationRequestData.getCrlEntryExtensionsJSONData());
        assertNotNull(revocationRequestData.getStatus());
        assertNotNull(revocationRequestData.toString());
    }
    
}