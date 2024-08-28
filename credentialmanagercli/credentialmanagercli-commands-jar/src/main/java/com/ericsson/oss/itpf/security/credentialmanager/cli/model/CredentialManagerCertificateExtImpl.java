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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CertificateExtensionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificateExt;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName;

/**
 * 
 * The class hold the Attributes of Certificate Extension
 * 
 */
public class CredentialManagerCertificateExtImpl implements
		CredentialManagerCertificateExt {

	/**
     * 
     */
	private static final long serialVersionUID = 2347119582899529848L;
	private Map<String, Attribute> attributes;
	private CredentialManagerSubjectAltName subjectAlternativeName;

	/**
	 * @param CertificateExtensionType
	 */
	public CredentialManagerCertificateExtImpl(
			final Object certificateextensionObj) {
		CertificateExtensionType certificateextension = null;

		if (certificateextensionObj != null
				&& certificateextensionObj instanceof CertificateExtensionType) {
			certificateextension = (CertificateExtensionType) certificateextensionObj;

		}

		if (certificateextension != null) {
			final SubjectAlternativeNameType subjectAltName = certificateextension
					.getSubjectalternativename();

			final CredentialManagerSubjectAltName credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(
					subjectAltName);
			attributes = new HashMap<String, Attribute>();
			subjectAlternativeName = credMsubjAltName;
			attributes.put(X509Extensions.SubjectAlternativeName.toString(),
					credMsubjAltName.getAttribute());
		} else {
			// build an empty object
			final SubjectAlternativeNameType dummySubj = new SubjectAlternativeNameType();
			this.subjectAlternativeName = new CredentialManagerSubjectAlternateNameImpl(dummySubj);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerCertificateExtension#getAttributes()
	 */
	@Override
	public Map<String, Attribute> getAttributes() {
		return attributes;
	}

	@Override
	public CredentialManagerSubjectAltName getSubjectAlternativeName() {
		return subjectAlternativeName;
	}

}
