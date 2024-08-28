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
package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import java.io.IOException;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.*;


public class CSRAttributesSubjectKeyIdentifierHandler {
	
	private static final Logger LOG = LogManager.getLogger(CSRAttributesSubjectKeyIdentifierHandler.class);
	
	public static Attribute[] getSubjectKeyIdentifierAttributes(
			final CredentialManagerProfileInfo profileInfo) {
	
		Attribute[] attributeArray = null;

		final CredentialManagerCertificateExtensions credentialManagerCertificateExtensions = profileInfo
				.getExtentionAttributes();

		if (credentialManagerCertificateExtensions == null) {
			return attributeArray;
		}

		final CredentialManagerSubjectKeyIdentifier credentialManagerSubjecyKeyIdentifier = profileInfo.getExtentionAttributes().getSubjectKeyIdentifier();

		if (credentialManagerSubjecyKeyIdentifier == null) {
			return attributeArray;
		}

		final Boolean isCritical = credentialManagerSubjecyKeyIdentifier.isCritical();
		
		/* 
		 * Convert String into byte [] 
		 */
		final byte [] keyidentifier = credentialManagerSubjecyKeyIdentifier.getKeyIdentifierAlgorithm().getBytes();
				
		final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(keyidentifier);

		final ExtensionsGenerator extGen = new ExtensionsGenerator();

		try {

			extGen.addExtension(Extension.subjectKeyIdentifier, isCritical,
					subjectKeyIdentifier);

		} catch (final IOException e) {
			LOG.error(ErrorMsg.API_ERROR_HANDLERS_ADD_CERTEXTENSION);
			//e.printStackTrace();
		}

		final Extensions extensions = extGen.generate();
		final Attribute attribute = new Attribute(
				PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(
						extensions));

		attributeArray = new Attribute[1];
		attributeArray[0] = attribute;
				
		return attributeArray;
	
	}
	
}
