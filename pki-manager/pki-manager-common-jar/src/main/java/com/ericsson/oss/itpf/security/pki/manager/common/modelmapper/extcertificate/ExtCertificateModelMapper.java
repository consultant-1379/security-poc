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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate;

import java.io.IOException;
import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Converts API models to JPA models and vice versa.
 * 
 */

public class ExtCertificateModelMapper {

    @Inject
    ExtCAMapper extCAMapper;

    @Inject
    PersistenceManager persistenceManager;

    /**
     * Convert Certificate Object model to CertificateData entity object.
     * 
     * @param certificate
     *            The certificate object.
     * 
     * @return CertificateData object.
     * 
     * @throws CertificateEncodingException
     *             Thrown in case of error occurred while encoding the data.
     */
    public CertificateData fromObjectModel(final Certificate certificate) throws CertificateEncodingException {

        final CertificateData certificateData = new CertificateData();
        certificateData.setId(certificate.getId());
        certificateData.setSerialNumber(certificate.getSerialNumber());
        certificateData.setIssuedTime(certificate.getNotAfter());
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateData.setStatus(certificate.getStatus().getId());
        certificateData.setIssuedTime(certificate.getIssuedTime());
        certificateData.setNotBefore(certificate.getX509Certificate().getNotBefore());
        certificateData.setNotAfter(certificate.getX509Certificate().getNotAfter());
        certificateData.setRevokedTime(certificate.getRevokedTime());

        if (certificate.getSubject() != null) {
            certificateData.setSubjectDN(certificate.getSubject().toASN1String());
        }

        if (certificate.getIssuer() != null) {
            final CAEntityData issuerCAEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH);
            certificateData.setIssuerCA(issuerCAEntityData);
            final Set<CertificateData> issuerCertificatesData = issuerCAEntityData.getCertificateAuthorityData().getCertificateDatas();
            for (final CertificateData issuerCertificateData : issuerCertificatesData) {
                if (issuerCertificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                    if (!certificate.getX509Certificate().getSubjectDN().getName().equals(certificate.getX509Certificate().getIssuerDN().getName())) {
                        certificateData.setIssuerCertificate(issuerCertificateData);
                        break;
                    }
                }
            }
        }

        return certificateData;
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model.
     * 
     * @param certificateDatas
     *            list of CertificateData entity objects
     * @return the list of Certificate api model objects.
     * 
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     */

    public List<Certificate> toObjectModel(final List<CertificateData> certificateDatas) throws IOException, CertificateException {

        final List<Certificate> certificateList = new ArrayList<Certificate>();
        for (final CertificateData certificateData : certificateDatas) {
            final Certificate certificate = toCertificate(certificateData);
            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * Convert CertificateData object to Certificate object model.
     * 
     * @param certificateData
     *            CertificateData object
     * 
     * @return the Certificate api model.
     * 
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */

    public Certificate toCertificate(final CertificateData certificateData) throws CertificateException, IOException {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());

        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setIssuedTime(certificateData.getIssuedTime());

        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }

        if (certificateData.getIssuerCA() != null) {
            final ExtCA caEntity = extCAMapper.toAPIFromModel(certificateData.getIssuerCA());
            certificate.setIssuer(caEntity.getCertificateAuthority());
            certificate.setIssuerCertificate(null);
        }

        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        certificate.setX509Certificate(x509Certificate);
        return certificate;

    }

}
