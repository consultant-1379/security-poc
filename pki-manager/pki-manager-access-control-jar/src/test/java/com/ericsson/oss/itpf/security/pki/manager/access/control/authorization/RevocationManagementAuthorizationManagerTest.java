/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.RevocationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.RevocationManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

/**
 * Test Class For RevocationManagementAuthorizationManager.
 * 
 * @author tcskaku
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class RevocationManagementAuthorizationManagerTest {
	@InjectMocks
	RevocationManagementAuthorizationManager revocationManagementAuthorizationManager;

	@Mock
	public Logger logger;

	@Mock
	SystemRecorder systemRecorder;

	@Mock
	private ContextUtility contextUtility;

	@Mock
	RevocationManagementAuthorizationHandler revocationManagementAuthorizationHandler;

	@Before
	public void setUpData() { 

	}

	@Test
	public void testAuthorizeRevokeEntityCertificate() {
		revocationManagementAuthorizationManager.authorizeRevokeEntityCertificate();

		Mockito.verify(logger).debug("Authorizing revoke entity certificate");
	} 

	@Test
	public void testAuthorizeRevokeCACertificate() {
		revocationManagementAuthorizationManager.authorizeRevokeCACertificate();

		Mockito.verify(logger).debug("Authorizing revoke ca certificate");
	}
	
}
