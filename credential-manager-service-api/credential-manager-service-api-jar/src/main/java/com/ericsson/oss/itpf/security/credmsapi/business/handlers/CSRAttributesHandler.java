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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Attribute;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;

public class CSRAttributesHandler {

    private final List<Attribute> attributeList = new ArrayList<Attribute>();

    public Attribute[] generateAttributes(final CredentialManagerProfileInfo profileInfo, final CredentialManagerCertificateExtension extentionFromXml) {

        /**
         * SubjectAltName
         */
        this.addAttributesToList(CSRAttributesSubAltNameHandler.getSubjectAltNameAttributes(profileInfo, extentionFromXml));

        /**
         * BasicConstraints
         */
        this.addAttributesToList(CSRAttributesBasicConstraintsHandler.getBasicConstraintsAttributes(profileInfo));

        /**
         * KeyUsage
         */
        this.addAttributesToList(CSRAttributesKeyUsageHandler.getKeyUsageAttributes(profileInfo));

        /**
         * ExtendedKeyUsage
         */
        this.addAttributesToList(CSRAttributesExtendedKeyUsageHandler.getExtendedKeyUsageAttributes(profileInfo));
        
        /**
         * SubjectKeyIdentifier
         */
        this.addAttributesToList(CSRAttributesSubjectKeyIdentifierHandler.getSubjectKeyIdentifierAttributes(profileInfo));

        /**
         * Add other extensions HERE
         */

        /**
         * Convert List to array
         */
        final Attribute[] attributes = this.attributeList.toArray(new Attribute[this.attributeList.size()]);

        /**
         * Clear List
         */
        this.attributeList.clear();

        return attributes;

    }

    /**
     * @param attributeArray
     */
    private void addAttributesToList(final Attribute[] attributeArray) {
        // null here means that the whole extension is empty in the entity data
        if (attributeArray != null) {
            for (final Attribute localAttribute : attributeArray) {
                // null here means that the single field inside the extension is empty
                if (localAttribute != null) {
                    this.attributeList.add(localAttribute);
                }
            }
        }
    }

}
