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

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidBasicConstraintsException;

/**
 * This class builds {@link org.bouncycastle.asn1.x509.BasicConstraints} extension for the certificate.
 * 
 */
public class BasicConstraintsBuilder {

    @Inject
    Logger logger;

    /**
     * Build {@link BasicConstraints} from CertificateExtension passed.
     * 
     * @param certificateExtension
     *            CertificateExtesnion that to be built as BasicConstraints.
     * @return Extension that has BasicConstraints object.
     * @throws InvalidBasicConstraintsException
     *             Thrown incase if any failures occur in building extension.
     */
    public Extension buildBasicConstraints(final CertificateExtension certificateExtension) throws InvalidBasicConstraintsException {

        final BasicConstraints basicConstraints = (BasicConstraints) certificateExtension;

        logger.debug("Adding BasicConstraints extension to certificate extensions {} ", basicConstraints);
        try {
            DEROctetString basicConstraintsExtension = null;
            Extension extension = null;
            final boolean pathLenConstraintDefined = basicConstraints.getPathLenConstraint() != null && basicConstraints.getPathLenConstraint() >= 0;

            if (basicConstraints.isCA() && pathLenConstraintDefined) {
                basicConstraintsExtension = new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(basicConstraints.getPathLenConstraint()));
            } else {
                basicConstraintsExtension = new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(basicConstraints.isCA()));
            }

            extension = new Extension(Extension.basicConstraints, basicConstraints.isCritical(), basicConstraintsExtension);

            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidBasicConstraintsException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }
}
