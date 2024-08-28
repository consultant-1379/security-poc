/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.CAEntityModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

/**
 * Converts API models to JPA models and vice versa.
 *
 * @author xaschar
 */
public class CertificateModelMapperV1 {

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityModelMapper caEntityModelMapperV1;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    ExtCAMapper extCAMapper;

    @Inject
    protected Logger logger;

    @Inject
    CRLGenerationInfoMapper cRLGenerationInfoMapper;

    /**
     * Convert Certificate Object model to CertificateData entity object.
     *
     * @param certificate
     *            The certificate object.
     * @return CertificateData object.
     *
     * @throws CertificateEncodingException
     *             Thrown in case of error occurred while encoding the data.
     * @throws PersistenceException
     *             Thrown in case of error occurred while finding Entity data.
     */
    public CertificateData fromApi(final Certificate certificate) throws CertificateEncodingException, PersistenceException {

        final CertificateData certificateData = new CertificateData();
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
        if (certificate.getSubjectAltName() != null) {
            certificateData.setSubjectAltName(JsonUtil.getJsonFromObject(certificate.getSubjectAltName()));
        }
        if (certificate.getIssuer() != null) {
            final CAEntityData issuerCAEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(),
                    Constants.CA_NAME_PATH);
            if (issuerCAEntityData != null) {
                certificateData.setIssuerCA(issuerCAEntityData);
                final Set<CertificateData> issuerCertificatesData = issuerCAEntityData.getCertificateAuthorityData().getCertificateDatas();
                for (final CertificateData issuerCertificateData : issuerCertificatesData) {
                    if (issuerCertificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
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
     * @param depth
     *            the amount of information/data required in the the returning object will be provided based on level passed.(LEVEL 0,1,2)
     * @return the list of Certificate api model objects.
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> toApi(final List<CertificateData> certificateDatas, final MappingDepth depth) throws CertificateException, IOException {

        switch (depth) {
        case LEVEL_0:
            return certificateSummary(certificateDatas);
        case LEVEL_1:
        case LEVEL_2:
            return certificateWithIssuerObject(certificateDatas, depth);
        default:
            logger.debug("Unknown mapping depth");
            return Collections.emptyList();
        }
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model.
     *
     * @param certificateDatas
     *            list of CertificateData entity objects
     * @return the list of Certificate api model objects.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> certificateSummary(final List<CertificateData> certificateDatas) throws CertificateException, IOException {

        final List<Certificate> certificateList = new ArrayList<>();
        for (final CertificateData certificateData : certificateDatas) {
            final Certificate certificate = toCertificateSummary(certificateData);

            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model.
     *
     * @param certificateDatas
     *            list of CertificateData entity objects
     * @param depth
     *            the amount of information/data required in the the returning object will be provided based on level passed.(LEVEL 1,2)
     * @return the list of Certificate api model objects.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> certificateWithIssuerObject(final List<CertificateData> certificateDatas, final MappingDepth depth)
            throws CertificateException, IOException {

        final List<Certificate> certificateList = new ArrayList<>();
        for (final CertificateData certificateData : certificateDatas) {
            final Certificate certificate = toCertificate(certificateData, depth);
            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * Convert CertificateData object to Certificate object model.
     *
     * @param certificateData
     *            CertificateData object
     * @param depth
     *            the amount of information/data required in the the returning object will be provided based on level passed.(LEVEL 1,2)
     * @return the Certificate api model.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    private Certificate toCertificate(final CertificateData certificateData, final MappingDepth depth) throws CertificateException, IOException {

        final Certificate certificate = toCertificateSummary(certificateData);
        if (certificateData.getIssuerCA() != null) {
            if (certificateData.getIssuerCertificate() != null) {
                logger.info("adding issuer to certifiate {} ", certificateData.getSubjectDN());
                mapToIssuerCertificate(certificate, certificateData);
            } else {
                logger.info("adding null issuer to certifiate");
                certificate.setIssuerCertificate(null);
            }
            mapIssuer(certificate, certificateData, depth);
        }
        return certificate;

    }

    private Certificate toCertificateSummary(final CertificateData certificateData) throws IOException, CertificateException {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());
        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setIssuedTime(certificateData.getIssuedTime());
        certificate.setRevokedTime(certificateData.getRevokedTime());
        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }
        certificate.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));
        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME)
                .getCertificate(certificateHolder);
        certificate.setX509Certificate(x509Certificate);
        return certificate;
    }

    private void mapToIssuerCertificate(final Certificate certificate, final CertificateData certificateData)
            throws CertificateException, IOException {

        if (certificateData.getIssuerCA().isExternalCA()) {
            final ExtCA extCA = extCAMapper.toAPIFromModel(certificateData.getIssuerCA());
            certificate.setIssuer(extCA.getCertificateAuthority());
        } else {
            certificate.setIssuerCertificate(toCertificateSummary(certificateData.getIssuerCertificate()));
            certificate.setIssuer(caEntityMapper.toCertAuthAPIModelWithoutIssuer(certificateData.getIssuerCA()));
        }
    }

    private void mapIssuer(final Certificate certificate, final CertificateData certificateData, final MappingDepth depth) {

        if (certificateData.getIssuerCA().isExternalCA()) {
            final ExtCA extCA = extCAMapper.toAPIFromModel(certificateData.getIssuerCA());
            certificate.setIssuer(extCA.getCertificateAuthority());
        } else {
            if (depth.equals(MappingDepth.LEVEL_1)) {
                final CAEntity caEntity = caEntityModelMapperV1.toApi(certificateData.getIssuerCA(), MappingDepth.LEVEL_0);
                certificate.setIssuer(caEntity.getCertificateAuthority());
            } else {
                final CAEntity caEntity = caEntityMapper.toAPIFromModel(certificateData.getIssuerCA());
                certificate.setIssuer(caEntity.getCertificateAuthority());
            }
        }
    }

    protected Subject toSubject(final String subjectString) {
        if (!ValidationUtils.isNullOrEmpty(subjectString)) {
            return new Subject().fromASN1String(subjectString);
        }

        return null;
    }

    protected SubjectAltName toSubjectAltName(final String subjectAltNameString) {
        if (!ValidationUtils.isNullOrEmpty(subjectAltNameString)) {
            return JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltNameString);
        }

        return null;
    }
}
