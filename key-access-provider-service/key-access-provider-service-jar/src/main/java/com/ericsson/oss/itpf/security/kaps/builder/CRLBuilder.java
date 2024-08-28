/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.kaps.builder;

import java.math.BigInteger;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;

/**
 * Class for build X509CRLBuilder object with {@link X509v2CRLBuilderHolder}
 * 
 * @author tcsrcho
 */
public class CRLBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CRLBuilder.class);

    /**
     * Converts {@link X509v2CRLBuilderHolder} to {@link X509v2CRLBuilder}
     * 
     * @param x509v2CRLBuilderHolder
     *            The X509v2CRLBuilderHolder Object
     * @param issuerDN
     *            The X500Principal Object
     * @return {@link X509v2CRLBuilder}
     * @throws InvalidCRLExtensionsException
     *             is thrown when CRL Extensions are not valid.
     */
    public X509v2CRLBuilder buildX509v2CRLBuilder(final X509v2CRLBuilderHolder x509v2CRLBuilderHolder, final X500Principal issuerDN)
            throws InvalidCRLExtensionsException {
        X500Name x500Name = null;
        if (issuerDN != null) {
            x500Name = X500Name.getInstance(issuerDN.getEncoded());
        } else {
            x500Name = new X500Name(x509v2CRLBuilderHolder.getSubjectDN());
        }
        final X509v2CRLBuilder x509v2CRLBuilder = new X509v2CRLBuilder(x500Name, x509v2CRLBuilderHolder.getThisUpdate());
        x509v2CRLBuilder.setNextUpdate(x509v2CRLBuilderHolder.getNextUpdate());
        final List<CertificateExtensionHolder> certificateExtensionHolders = x509v2CRLBuilderHolder.getExtensionHolders();
        try {
            for (final CertificateExtensionHolder certificateExtensionHolder : certificateExtensionHolders) {
                x509v2CRLBuilder.addExtension(new ASN1ObjectIdentifier(certificateExtensionHolder.getExtnId()),
                        certificateExtensionHolder.isCritical(), certificateExtensionHolder.getValue());
            }
        } catch (CertIOException certIOException) {
            LOGGER.error(ErrorMessages.INVALID_CSR_EXTENSION + certIOException.getMessage());
            throw new InvalidCRLExtensionsException(ErrorMessages.INVALID_CSR_EXTENSION + certIOException.getMessage(), certIOException);
        }

        final List<RevokedCertificateInfoHolder> revokedCertificatesInfoHolders = x509v2CRLBuilderHolder.getRevokedCertificateInfoHolders();

        for (final RevokedCertificateInfoHolder revokedCertificatesInfoHolder : revokedCertificatesInfoHolders) {
            final String serialNumber = revokedCertificatesInfoHolder.getSerialNumber();

            if (revokedCertificatesInfoHolder.getInvalidityDate() == null) {
                x509v2CRLBuilder.addCRLEntry(new BigInteger(serialNumber, 16), revokedCertificatesInfoHolder.getRevocationDate(),
                        revokedCertificatesInfoHolder.getRevocationReason());
            } else {
                x509v2CRLBuilder.addCRLEntry(new BigInteger(serialNumber, 16), revokedCertificatesInfoHolder.getRevocationDate(),
                        revokedCertificatesInfoHolder.getRevocationReason(), revokedCertificatesInfoHolder.getInvalidityDate());
            }
        }

        return x509v2CRLBuilder;
    }
}
