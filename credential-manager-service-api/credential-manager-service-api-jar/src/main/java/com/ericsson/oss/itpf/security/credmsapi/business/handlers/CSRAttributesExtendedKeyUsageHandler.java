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

public class CSRAttributesExtendedKeyUsageHandler {

    private static final Logger LOG = LogManager.getLogger(CSRAttributesExtendedKeyUsageHandler.class);
	
	public static Attribute[] getExtendedKeyUsageAttributes(
			final CredentialManagerProfileInfo profileInfo) {

		Attribute[] attributeArray = null;

		final CredentialManagerCertificateExtensions credentialManagerCertificateExtensions = profileInfo
				.getExtentionAttributes();

		if (credentialManagerCertificateExtensions == null) {
			return attributeArray;
		}

		final CredentialManagerExtendedKeyUsage credentialManagerExtendedKeyUsage = profileInfo
				.getExtentionAttributes().getExtendedKeyUsage();

		if (credentialManagerExtendedKeyUsage == null) {
			return attributeArray;
		}

		final Boolean isCritical = credentialManagerExtendedKeyUsage.isCritical();

		final List<CredentialManagerKeyPurposeId> credManKeyPurposeIdList = credentialManagerExtendedKeyUsage
				.getKeyPurposeId();

		if (credManKeyPurposeIdList.isEmpty()) {
			return attributeArray;
		}

		final KeyPurposeId[] keyPurposeIdArray = new KeyPurposeId[credManKeyPurposeIdList
				.size()];

		int keyPurposeCounter = 0;
		for (final CredentialManagerKeyPurposeId credManKeyPurposeId : credManKeyPurposeIdList) {

			switch (credManKeyPurposeId.value()) {

			case "id_kp_clientAuth":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_clientAuth;
				break;

			case "id_kp_codeSigning":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_codeSigning;
				break;

			case "id_kp_emailProtection":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_emailProtection;
				break;

			case "id_kp_timeStamping":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_timeStamping;
				break;

			case "id_kp_OCSPSigning":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_OCSPSigning;
				break;

			case "id_kp_serverAuth":
				keyPurposeIdArray[keyPurposeCounter++] = KeyPurposeId.id_kp_serverAuth;
				break;

			}
		}

		final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				keyPurposeIdArray);

		final ExtensionsGenerator extGen = new ExtensionsGenerator();

		try {

			extGen.addExtension(Extension.extendedKeyUsage, isCritical,
					extendedKeyUsage);

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
