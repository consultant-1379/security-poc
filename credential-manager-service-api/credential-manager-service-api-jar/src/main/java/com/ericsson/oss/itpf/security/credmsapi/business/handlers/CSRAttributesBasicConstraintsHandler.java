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

import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerExtensionBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;

public class CSRAttributesBasicConstraintsHandler {

    public static Attribute[] getBasicConstraintsAttributes(final CredentialManagerProfileInfo profileInfo) {

        if (profileInfo.getExtentionAttributes() == null) {
            return null;
        }

        if (profileInfo.getExtentionAttributes().getBasicConstraints() == null) {
            return null;
        }

        final CredentialManagerExtensionBasicConstraints basicConstraintsFromProfile = new CredentialManagerExtensionBasicConstraints(profileInfo.getExtentionAttributes().getBasicConstraints());

        final Attribute[] basicConstraintsAttributes = new Attribute[basicConstraintsFromProfile.getAttributes().size()];

        basicConstraintsFromProfile.getAttributes().values().toArray(basicConstraintsAttributes);

        return basicConstraintsAttributes;
    }
}
