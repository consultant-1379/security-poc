/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import java.io.IOException;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidAuthorityInformationAccessException;

/**
 * This class builds {@link org.bouncycastle.asn1.x509.AuthorityInformationAccess} extension for the certificate.
 * 
 */
public class AuthorityInformationAccessBuilder {

    @Inject
    Logger logger;

    /**
     * Builds {@link AuthorityInformationAccess} from the extension passed.
     * 
     * @param certificateExtension
     *            certificate extension that to be built as AuthorityInformationAccess
     * @return Extension object that has AuthorityInformationAccess.
     * @throws InvalidAuthorityInformationAccessException
     *             Thrown incase if any failures occur in building extension.
     */
    public Extension buildAuthorityInformationAccess(final CertificateExtension certificateExtension) throws InvalidAuthorityInformationAccessException {

        final AuthorityInformationAccess authorityInformationAccess = (AuthorityInformationAccess) certificateExtension;

        logger.debug("Adding authorityInformationAccess extension to certificate extensions {} ", authorityInformationAccess);
        try {
            Extension extension = null;
            if (authorityInformationAccess != null && !authorityInformationAccess.getAccessDescriptions().isEmpty()) {

                final ASN1EncodableVector authrorityInformationAccess = addAccessDescriptionstoAIA(authorityInformationAccess);
                final DEROctetString authrorityInformationAccessExtension = new DEROctetString(new DERSequence(authrorityInformationAccess));

                extension = new Extension(Extension.authorityInfoAccess, authorityInformationAccess.isCritical(), authrorityInformationAccessExtension);
            }
            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidAuthorityInformationAccessException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    private ASN1EncodableVector addAccessDescriptionstoAIA(final AuthorityInformationAccess authorityInformationAccess) {

        final ASN1EncodableVector authorityInfoAccess = new ASN1EncodableVector();

        final List<AccessDescription> list = authorityInformationAccess.getAccessDescriptions();

        for (final AccessDescription accessDescription : list) {
            if (AccessMethod.CA_ISSUER == accessDescription.getAccessMethod()) {
                final org.bouncycastle.asn1.x509.AccessDescription caIssuers = new org.bouncycastle.asn1.x509.AccessDescription(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(accessDescription.getAccessLocation())));

                authorityInfoAccess.add(caIssuers);
            } else if (AccessMethod.OCSP == accessDescription.getAccessMethod() && accessDescription.getAccessLocation() != null) {
                final org.bouncycastle.asn1.x509.AccessDescription ocsp = new org.bouncycastle.asn1.x509.AccessDescription(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(accessDescription.getAccessLocation())));
                authorityInfoAccess.add(ocsp);
            }
        }
        return authorityInfoAccess;
    }
}
