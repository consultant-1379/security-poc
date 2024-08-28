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

import org.bouncycastle.asn1.x509.Attribute;

import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerExtensionSubAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;

public class CSRAttributesSubAltNameHandler {

	/**
	 * @param profileInfo
	 * @param extentionFromXml
	 * @param attr
	 * @return
	 */
	public static Attribute[] getSubjectAltNameAttributes(
			final CredentialManagerProfileInfo profileInfo,
			final CredentialManagerCertificateExtension extentionFromXml) {

		if ((extentionFromXml != null)
		                && (extentionFromXml.getSubjectAlternativeName() != null)
				&& (!extentionFromXml.getSubjectAlternativeName().isEmpty())) {
			//System.out.print("XML path \n");
			final Attribute[] attxml = new Attribute[extentionFromXml
					.getAttributes().size()];

			extentionFromXml.getAttributes().values().toArray(attxml);

			return attxml;
		} else {
			//System.out.print("Profile path \n");
			final CredentialManagerExtensionSubAltName certificationExtentionFromProfile = new CredentialManagerExtensionSubAltName(
					profileInfo.getSubjectDefaultAlternativeName());

			if (certificationExtentionFromProfile.getAttributes() != null) {
				final Attribute[] attprofile = new Attribute[certificationExtentionFromProfile
						.getAttributes().size()];

				certificationExtentionFromProfile.getAttributes().values()
						.toArray(attprofile);

				return attprofile;
			}
			return null;
		}
	}

}
