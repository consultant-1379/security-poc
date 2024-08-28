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
package com.ericsson.oss.itpf.security.credmservice.profiles.impl;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.CredentialManagerProfiles;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;

public class CredentialManagerProfilesImpl implements CredentialManagerProfiles {

	/**
     * 
     */
	private static final long serialVersionUID = -1339739185679099076L;
	private final List<XmlTrustProfile> trustProfiles = new ArrayList<XmlTrustProfile>();
	private final List<XmlEntityProfile> entityProfiles = new ArrayList<XmlEntityProfile>();
	private final List<XmlCertificateProfile> certificateProfiles = new ArrayList<XmlCertificateProfile>();

	public CredentialManagerProfilesImpl(final Object profilesObj)
			throws CredentialManagerProfilesException {
		XmlProfiles profiles;

		if (profilesObj != null && profilesObj instanceof XmlProfiles) {
			profiles = (XmlProfiles) profilesObj;
		} else {
			throw new CredentialManagerProfilesException(
					"Loading information of XML Applications Type...[Failed]");
		}

		if (profiles.getTrustProfiles() != null) {
			for (final XmlTrustProfile profile : profiles.getTrustProfiles()
					.getTrustProfile()) {
				if (profile != null) {
					trustProfiles.add(profile);
				}
			}
		}

		if (profiles.getEntityProfiles() != null) {
			for (final XmlEntityProfile profile : profiles.getEntityProfiles()
					.getEntityProfile()) {
				if (profile != null) {
					entityProfiles.add(profile);
				}
			}
		}

		if (profiles.getCertificateProfiles() != null) {
			for (final XmlCertificateProfile profile : profiles
					.getCertificateProfiles().getCertificateProfile()) {
				if (profile != null) {
					certificateProfiles.add(profile);
				}
			}
		}

	}

	@Override
	public List<XmlTrustProfile> getTrustProfiles() {
		return trustProfiles;
	}

	@Override
	public List<XmlEntityProfile> getEntityProfiles() {
		return entityProfiles;
	}

	@Override
	public List<XmlCertificateProfile> getCertificateProfiles() {
		return certificateProfiles;
	}

}
