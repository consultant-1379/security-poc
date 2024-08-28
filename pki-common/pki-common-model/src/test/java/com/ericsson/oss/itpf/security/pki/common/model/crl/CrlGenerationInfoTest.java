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
package com.ericsson.oss.itpf.security.pki.common.model.crl;

/**
 * Test class for CrlGenerationInfo.
 */
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.lang.reflect.Method;
import java.text.ParseException;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CrlGenerationInfoSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CrlGenerationInfoTest extends EqualsTestCase{ 
	@InjectMocks
	CrlGenerationInfo crlGenerationInfo;

	/* (non-Javadoc)
	 * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
	 */ 
	@Override
	protected CrlGenerationInfo createInstance() throws ParseException,
			DatatypeConfigurationException {
		return CrlGenerationInfoSetUpData.getCrlGenerationInfoEqual();  
	}

	/* (non-Javadoc)
	 * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
	 */
	@Override
	protected CrlGenerationInfo createNotEqualInstance() throws ParseException,
			DatatypeConfigurationException {
		return CrlGenerationInfoSetUpData.getCrlGenerationInfoNotEqual();  
		}
	
	@Override
    @Test
    public void testWithEachFieldNull() throws Exception {  
        final Object crlGenerationInfo = createInstance(); 
        final Class<? extends Object> CrlGenerationInfoClass = crlGenerationInfo.getClass();
        final Object nullObject = null; 
        final Method[] methods = CrlGenerationInfoClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance(); 
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);
                    assertNotEquals(crlGenerationInfo, tempObject1);
                    assertNotEquals(tempObject1, crlGenerationInfo);
                    assertEquals(tempObject1, tempObject2); 
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }

}

