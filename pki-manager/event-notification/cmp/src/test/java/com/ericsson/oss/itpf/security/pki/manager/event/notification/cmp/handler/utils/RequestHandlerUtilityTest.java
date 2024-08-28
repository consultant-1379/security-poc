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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;


@RunWith(PowerMockRunner.class)
@PrepareForTest(DOMUtil.class)
public class RequestHandlerUtilityTest {

	@InjectMocks
	RequestHandlerUtility requestHandlerUtility;
	
	@Mock
	CredentialsManager credentialsManager;
	
	
	@Mock
	DigitalSignatureValidator digitalSignatureValidator;
	
	@Test
	public void loadAndValidateRequest()
	{
		
		byte[] xMLSignedData = new byte[]{1};
		
		PowerMockito.mockStatic(DOMUtil.class);

		requestHandlerUtility.loadAndValidateRequest(xMLSignedData);
	}
}
