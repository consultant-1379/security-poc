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
import java.util.List;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.*;

public class CSRAttributesKeyUsageHandler {

	private static final Logger LOG = LogManager.getLogger(CSRAttributesKeyUsageHandler.class);
	
	public static Attribute[] getKeyUsageAttributes(
			final CredentialManagerProfileInfo profileInfo) {

		Attribute[] attributeArray = null;

		final CredentialManagerCertificateExtensions credentialManagerCertificateExtensions = profileInfo
				.getExtentionAttributes();

		if (credentialManagerCertificateExtensions == null) {
			return attributeArray;
		}

		final CredentialManagerKeyUsage credentialManagerKeyUsage = profileInfo
				.getExtentionAttributes().getKeyUsage();

		if (credentialManagerKeyUsage == null) {
			return attributeArray;
		}

		final Boolean isCritical = credentialManagerKeyUsage.isCritical();

		final List<CredentialManagerKeyUsageType> credManKeyUsageTypeList = credentialManagerKeyUsage
				.getKeyUsageType();

		int globalkeyUsage = 0;

		if (!credManKeyUsageTypeList.isEmpty()) {

			attributeArray = new Attribute[1];

			for (final CredentialManagerKeyUsageType credManKeyUsageType : credManKeyUsageTypeList) {

				switch (credManKeyUsageType.value()) {

				case "digitalSignature":
					globalkeyUsage |= KeyUsage.digitalSignature;
					break;

				case "nonRepudiation":
					globalkeyUsage |= KeyUsage.nonRepudiation;
					break;

				case "keyEncipherment":
					globalkeyUsage |= KeyUsage.keyEncipherment;
					break;

				case "dataEncipherment":
					globalkeyUsage |= KeyUsage.dataEncipherment;
					break;

				case "keyAgreement":
					globalkeyUsage |= KeyUsage.keyAgreement;
					break;

				case "keyCertSign":
					globalkeyUsage |= KeyUsage.keyCertSign;
					break;

				case "cRLSign":
					globalkeyUsage |= KeyUsage.cRLSign;
					break;

				case "encipherOnly":
					globalkeyUsage |= KeyUsage.encipherOnly;
					break;

				case "decipherOnly":
					globalkeyUsage |= KeyUsage.decipherOnly;
					break;

				}
			}
		} else {

			return attributeArray;

		}

		final KeyUsage keyUsage = new KeyUsage(globalkeyUsage);

		final ExtensionsGenerator extGen = new ExtensionsGenerator();

		try {

			extGen.addExtension(Extension.keyUsage, isCritical,
					keyUsage);

		} catch (final IOException e) {
			LOG.error(ErrorMsg.API_ERROR_HANDLERS_ADD_CERTEXTENSION);
			//e.printStackTrace();
		}

		final Extensions extensions = extGen.generate();
		final Attribute attribute = new Attribute(
				PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(
						extensions));

		attributeArray[0] = attribute;

		return attributeArray;

	}
}
