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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.common.CDPSEntitySetUpData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.*;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;

/**
 * This class used to test CDPSEntityData functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CDPSEntityDataTest extends EqualsTestCase {

    @InjectMocks
    CDPSEntityData cdpsEntityData;

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.pki.cdps.common.persistence.common.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CDPSEntityData createCDPSEntityDataInstance() {
        return new CDPSEntitySetUpData().getCDPSEntityForEqual();
    }

    /*
     * (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.pki.cdps.common.persistence.common.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CDPSEntityData createNotEqualCDPSEntityDataInstance() {
        return new CDPSEntitySetUpData().getCDPSEntityForNotEqual();
    }

    /**
     * Method to test equals method of {@link CDPSEntityData}
     */

    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {

        final CDPSEntityData cdpsEntityData = createCDPSEntityDataInstance();
        final Class<? extends CDPSEntityData> tClass = cdpsEntityData.getClass();
        final CDPSEntityData nullCDPSEntityData = null;
        final Method[] methods = tClass.getMethods();

        CDPSEntityData cdspsEtityDataTemp = null;
        CDPSEntityData cdpsEntityDataTemperory = null;
        for (Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    cdspsEtityDataTemp = createCDPSEntityDataInstance();
                    cdpsEntityDataTemperory = createCDPSEntityDataInstance();
                    method.invoke(cdpsEntityDataTemperory, nullCDPSEntityData);
                    method.invoke(cdspsEtityDataTemp, nullCDPSEntityData);
                    assertNotEquals(cdpsEntityData, cdspsEtityDataTemp);
                    assertNotEquals(cdspsEtityDataTemp, cdpsEntityData);
                    assertEquals(cdspsEtityDataTemp, cdpsEntityDataTemperory);
                }
            }
        }
    }
}