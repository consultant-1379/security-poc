/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.impl;

import com.ericsson.oss.itpf.security.credmservice.api.PKIProfileFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class PKIProfileFactoryImpl implements PKIProfileFactory {

    private Long id;
    private String name;

    private ProfileType profileType;

    @Override
    public AbstractProfile buildForRequest() throws CredentialManagerInvalidArgumentException {
        validateForRequest();
        AbstractProfile profile = null;

        if (profileType == ProfileType.CERTIFICATE_PROFILE) {
            profile = new CertificateProfile();
        } else if (profileType == ProfileType.ENTITY_PROFILE) {
            profile = new EntityProfile();
        } else if (profileType == ProfileType.TRUST_PROFILE) {
            profile = new TrustProfile();
        } else {
            throw new CredentialManagerInvalidArgumentException("ProfileType not managed");
        }
        if (id != null) {
            profile.setId(id);
        }
        if (name != null) {
            profile.setName(name);
        }
        return profile;
    }

    @Override
    public PKIProfileFactory setId(final long id) {
        this.id = id;
        return this;
    }

    @Override
    public PKIProfileFactory setName(final String name) {
        this.name = name;
        return this;
    }

    @Override
    public PKIProfileFactory setProfileType(final ProfileType profileType) {
        this.profileType = profileType;
        return this;
    }

    private void validateForRequest() throws CredentialManagerInvalidArgumentException {
        if (!idIsValid() && !nameIsValid() || idIsValid() && nameIsValid() || !profileTypeIsValid()) {
            throw new CredentialManagerInvalidArgumentException("Id or Name or ProfileType are empty");
        }
    }

    private boolean nameIsValid() {
        return name != null && !name.isEmpty();
    }

    private boolean idIsValid() {
        return id != null;
    }

    private boolean profileTypeIsValid() {
        return profileType != null;
    }

}
