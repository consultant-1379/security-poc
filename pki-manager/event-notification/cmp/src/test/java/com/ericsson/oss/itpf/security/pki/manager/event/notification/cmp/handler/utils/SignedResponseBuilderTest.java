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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;

@RunWith(PowerMockRunner.class)
@PrepareForTest(AttachedSignatureXMLBuilder.class)
public class SignedResponseBuilderTest {

	@InjectMocks
	SignedResponseBuilder signedResponseBuilder;

	@Mock
	CMPResponse cMPResponse;

	@Mock
	RevocationResponse revocationResponse;

	@Mock
	X509Certificate certificate;

	@Mock
	CredentialsManager credentialsManager;

	@Mock
	PrivateKey signerKey;

	@Test
	public void buildSignedCMPResponse() {

		setupData();
		signedResponseBuilder.buildSignedCMPResponse(cMPResponse);

	}

	
	@Test
	public void buildSignedRevocationResponse() {

		setupData();
		
		signedResponseBuilder.buildSignedRevocationResponse(revocationResponse);
	}
	
	public void setupData()
	{
		PowerMockito.mockStatic(AttachedSignatureXMLBuilder.class);

		Mockito.when(credentialsManager.getSignerCertificate()).thenReturn(
				certificate);
		Mockito.when(credentialsManager.getSignerPrivateKey()).thenReturn(
				signerKey);

		Mockito.when(
				AttachedSignatureXMLBuilder.build(certificate, signerKey,
						cMPResponse)).thenReturn(new byte[] { 1 });
		
	}

}
