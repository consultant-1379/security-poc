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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;

public class CredentialManagerExtensionBasicConstraints {

    private static final Logger LOG = LogManager.getLogger(CredentialManagerExtensionBasicConstraints.class);

    private Map<String, Attribute> attributes;
    private final static String BASICCONSTRAINTSNAME = "basicConstraintsName";

    /**
     * 
     */
    public CredentialManagerExtensionBasicConstraints(final CredentialManagerBasicConstraints credentialManagerBasicConstraints) {

        if (credentialManagerBasicConstraints != null) {

            this.attributes = new HashMap<String, Attribute>();

            this.attributes.put(BASICCONSTRAINTSNAME, this.generateAttribute(credentialManagerBasicConstraints));

        }

    }

    /**
     * @return the attributes
     */
    public Map<String, Attribute> getAttributes() {
        return this.attributes;
    }

    /**
     * @return the basicConstraintsName
     */
    public String getBasicConstraintsName() {
        return BASICCONSTRAINTSNAME;
    }

    private Attribute generateAttribute(final CredentialManagerBasicConstraints localCredentialManagerBasicConstraints) {

        if (!localCredentialManagerBasicConstraints.isEnabled()) {
            return null;
        }

        /**
         * constructor
         * 
         * getPathLenConstraint() from Profile always returns an int value (0..MAX)
         * 
         */
        BasicConstraints bcBasicConstraints = null;

        if (localCredentialManagerBasicConstraints.isCA()) {

            bcBasicConstraints = new BasicConstraints(localCredentialManagerBasicConstraints.getPathLenConstraint());

        } else {

            bcBasicConstraints = new BasicConstraints(false);
        }

        /**
         * conversion to Bouncy Castle Extension
         */
        final ExtensionsGenerator extGen = new ExtensionsGenerator();

        try {
            extGen.addExtension(Extension.basicConstraints, false, bcBasicConstraints);
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_ADD_CERTEXTENSION);
            //e.printStackTrace();
        }

        final Extensions extensions = extGen.generate();
        return (new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions)));

    }

}
