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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.SANConvertHandler;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;

/**
 * 
 * The class hold the Attributes of Certificate Extension
 * 
 */
public class CredentialManagerExtensionSubAltName {


        private Map<String, Attribute> attributes;
        private String subjectAlternativeName;

        /**
	 * @param CertificateExtensionType
	 */
	public CredentialManagerExtensionSubAltName(
			final Object certificateextensionprofileObj) {
		CredentialManagerSubjectAltName certificateextensionprofile = null;

		if (certificateextensionprofileObj != null
				&& certificateextensionprofileObj instanceof CredentialManagerSubjectAltName) {
			certificateextensionprofile = (CredentialManagerSubjectAltName) certificateextensionprofileObj;

		}

		if (certificateextensionprofile != null) {

			/**
			 * Riempire campi del subjectAltName con certificateextensionprofile
			 */
			final SANConvertHandler convertHandler = new SANConvertHandler();
			final SubjectAlternativeNameType subjectAltName;

			subjectAltName = convertHandler
					.serviceToXml(certificateextensionprofile);

			final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(
					subjectAltName);

			attributes = new HashMap<String, Attribute>();
			subjectAlternativeName = credMsubjAltName
					.getSubjectAlternativeName();
			attributes.put(X509Extensions.SubjectAlternativeName.toString(),
					credMsubjAltName.getAttribute());

		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model.
	 * CredentialManagerCertificateExtension#getAttributes()
	 */
	public Map<String, Attribute> getAttributes() {
		return attributes;
	}

	public String getSubjectAlternativeName() {
		return subjectAlternativeName;
	}

}
