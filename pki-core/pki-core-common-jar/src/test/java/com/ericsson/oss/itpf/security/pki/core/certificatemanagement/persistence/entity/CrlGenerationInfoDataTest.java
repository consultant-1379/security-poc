/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.entity;

/**
 * Test Class for CrlGenerationInfoData.
 */
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.core.common.Data.CrlGenerationInfoSetUpData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CrlGenerationInfoData;

@RunWith(MockitoJUnitRunner.class)
public class CrlGenerationInfoDataTest extends EqualsTestCase{  
	
	@InjectMocks
	CrlGenerationInfoData crlGenerationInfoData;

	/* (non-Javadoc)
	 * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
	 */
	@Override
	protected CrlGenerationInfoData createInstance() {
		return CrlGenerationInfoSetUpData.getCrlGenerationInfoData(); 
	}

	/* (non-Javadoc)
	 * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
	 */
	@Override
	protected CrlGenerationInfoData createNotEqualInstance() {
		return CrlGenerationInfoSetUpData.getCrlGenerationInfoDataForNotEqual(); 
	}
	
	/**
     * Method to test equals method of {@link CrlGenerationInfoData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception { 
        final Object crlGenerationInfoData = createInstance();
        final Class<? extends Object> CrlGenerationInfoDataClass = crlGenerationInfoData.getClass(); 
        final Object nullObject = null; 
        final Method[] methods = CrlGenerationInfoDataClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".")) {
                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);
                    assertNotEquals(crlGenerationInfoData, tempObject1);
                    assertNotEquals(tempObject1, crlGenerationInfoData);
                    assertEquals(tempObject1, tempObject2); 
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }
    
    /**
     * Method to test getter method of {@link CrlGenerationInfoData}
     */
    @Test
    public void testMethods() {
    	crlGenerationInfoData = new CrlGenerationInfoSetUpData().getCrlGenerationInfoData();
        assertNotNull(crlGenerationInfoData.getId());
        assertNotNull(crlGenerationInfoData.getValidityPeriod());
        assertNotNull(crlGenerationInfoData.getCaCertificate());
        assertNotNull(crlGenerationInfoData.getClass());
        assertNotNull(crlGenerationInfoData.getCrlExtensionsJSONData());
        assertNotNull(crlGenerationInfoData.getOverlapPeriod());
        assertNotNull(crlGenerationInfoData.getSignatureAlgorithm());
        assertNotNull(crlGenerationInfoData.getSkewCrlTime());
        assertNotNull(crlGenerationInfoData.getVersion());
        assertNotNull(crlGenerationInfoData.toString());
    }
}
