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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

/**
 * Converts API models to JPA models and vice versa.
 *
 */
public class CertificateModelMapper {

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    ExtCAMapper extCAMapper;

    /**
     * Convert Certificate Object model to CertificateData entity object.
     *
     * @param certificate
     *            The certificate object.
     * @param issuerCAEntityData
     *            The CAEntityData Object.
     * @return CertificateData object.
     *
     * @throws CertificateEncodingException
     *             Thrown in case of error occurred while encoding the data.
     * @throws PersistenceException
     *             Thrown in case of error occurred while finding Entity data.
     */
    public CertificateData fromObjectModel(final Certificate certificate) throws CertificateEncodingException, PersistenceException {

        final CertificateData certificateData = new CertificateData();
        // certificateData.setId(certificate.getId());
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
            final CAEntityData issuerCAEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH);
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
     * @return the list of Certificate api model objects.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> toObjectModel(final List<CertificateData> certificateDatas) throws CertificateException, IOException {

        final List<Certificate> certificateList = new ArrayList<Certificate>();
        for (final CertificateData certificateData : certificateDatas) {
            final Certificate certificate = toCertificate(certificateData);
            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model. Embedded objects are mapped based on embeddedObjectsRequired flag.
     *
     * @param certificateDatas
     *            list of CertificateData entity objects
     * @param embeddedObjectsRequired
     *            Embedded objects are mapped based on this parameter. If value is true, embedded objects are mapped. If false, same are not mapped
     * @return the list of Certificate api model objects.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> toObjectModel(final List<CertificateData> certificateDatas, final boolean embeddedObjectsRequired) throws CertificateException, IOException {

        final List<Certificate> certificateList = new ArrayList<Certificate>();
        for (final CertificateData certificateData : certificateDatas) {
            final Certificate certificate = toCertificate(certificateData, embeddedObjectsRequired);
            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * Convert CertificateData entity object to Certificate object model without embedded objects.
     *
     * @param certificateData
     *            list of CertificateData entity objects
     * @param embeddedObjectsRequired
     *            Embedded objects are mapped based on this parameter. If value is true, embedded objects are mapped. If false, same are not mapped
     * @return the Certificate api model object
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public Certificate toObjectModel(final CertificateData certificateData, final boolean embeddedObjectsRequired) throws CertificateException, IOException {

        return toCertificate(certificateData, embeddedObjectsRequired);
    }

    /**
     * Convert CertificateData object to Certificate object model.
     *
     * @param certificateData
     *            CertificateData object
     * @param isIssuerDataRequired
     *            is Issuer Data Required
     * @return the Certificate api model.
     *
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    private Certificate toCertificate(final CertificateData certificateData, final boolean isIssuerDataRequired) throws CertificateException, IOException {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());

        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setIssuedTime(certificateData.getIssuedTime());
        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }
        certificate.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));

        if (isIssuerDataRequired && certificateData.getIssuerCA() != null) {

            if (certificateData.getIssuerCertificate() != null) {
                certificate.setIssuerCertificate(mapToIssuerCertificate(certificateData.getIssuerCertificate()));
            } else {
                certificate.setIssuerCertificate(null);
            }

            if (certificateData.getIssuerCA().isExternalCA()) {
                final ExtCA extCA = extCAMapper.toAPIFromModel(certificateData.getIssuerCA());
                certificate.setIssuer(extCA.getCertificateAuthority());
            } else {
                final CAEntity caEntity = caEntityMapper.toAPIFromModel(certificateData.getIssuerCA());
                certificate.setIssuer(caEntity.getCertificateAuthority());
            }
        }

        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        certificate.setX509Certificate(x509Certificate);
        return certificate;

    }

    /**
     * Convert CertificateData object to Certificate object model.
     *
     * @param certificateData
     *            CertificateData object
     * @return the Certificate api model.
     *
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure of certificate.
     * @throws CertificateException
     *             Thrown in the event of not able to build the certificate from byte array.
     */

    public Certificate toCertificate(final CertificateData certificateData) throws CertificateException, IOException {
        return toCertificate(certificateData, true);
    }

    /**
     * Convert certificateRequest API model to CertificateRequestData JPA model.
     *
     * @param certificateRequest
     *            The CertificateRequest object.
     * @return certificateRequestData The CertificateRequestData object.
     * @throws IOException
     *             Thrown in case of any exception occurs while converting certificateRequest into byte array.
     */
    public CertificateRequestData toCertificateRequestData(final CertificateRequest certificateRequest) throws IOException {

        final CertificateRequestData certificateRequestData = new CertificateRequestData();

        if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
            final PKCS10CertificationRequestHolder pkcs10RequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
            certificateRequestData.setCsr(pkcs10RequestHolder.getCertificateRequest().getEncoded());

        } else if (certificateRequest.getCertificateRequestHolder() instanceof CRMFRequestHolder) {
            final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
            certificateRequestData.setCsr(crmfRequestHolder.getCertificateRequest().getEncoded());
        }
        certificateRequestData.setStatus(CertificateRequestStatus.ISSUED.getId());

        return certificateRequestData;

    }

    /**
     * Convert CertificateGenerationInfo API model to CertificateGenerationInfoData JPA model.
     *
     * @param certificateGenerationInfo
     *            The CertificateGenerationInfo object.
     * @return certificateGenerationInfoData The certificateGenerationInfoData object.
     *
     * @throws PersistenceException
     *             Thrown when internal db error occurs while mapping CertificateGenerationInfo
     */
    public CertificateGenerationInfoData toCertificateGenerationInfoData(final CertificateGenerationInfo certificateGenerationInfo) throws PersistenceException {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        if (certificateGenerationInfo.getValidity() != null) {
            certificateGenerationInfoData.setValidity(certificateGenerationInfo.getValidity().toString());
        }

        certificateGenerationInfoData.setSubjectUniqueIdentifier(certificateGenerationInfo.isSubjectUniqueIdentifier());
        certificateGenerationInfoData.setIssuerUniqueIdentifier(certificateGenerationInfo.isIssuerUniqueIdentifier());
        certificateGenerationInfoData.setSubjectUniqueIdentifierValue(certificateGenerationInfo.getSubjectUniqueIdentifierValue());
        certificateGenerationInfoData.setCertificateVersion(certificateGenerationInfo.getVersion());

        if (certificateGenerationInfo.getSkewCertificateTime() != null) {
            certificateGenerationInfoData.setSkewCertificateTime(certificateGenerationInfo.getSkewCertificateTime().toString());

        }

        setAlgorithmData(certificateGenerationInfo, certificateGenerationInfoData);

        certificateGenerationInfoData.setRequestType(certificateGenerationInfo.getRequestType());
        certificateGenerationInfoData.setForExternalCA(certificateGenerationInfo.isForExternalCA());

        final String certificateExtensionsJSONData = JsonUtil.getJsonFromObject(certificateGenerationInfo.getCertificateExtensions());
        certificateGenerationInfoData.setCertificateExtensionsJSONData(certificateExtensionsJSONData);

        seEntityInfo(certificateGenerationInfo, certificateGenerationInfoData);

        if (certificateGenerationInfo.getIssuerCA() != null) {
            final CAEntityData issuerCAEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificateGenerationInfo.getIssuerCA().getName(), Constants.CA_NAME_PATH);
            certificateGenerationInfoData.setIssuerCA(issuerCAEntityData);
        }

        return certificateGenerationInfoData;
    }

    private void setAlgorithmData(final CertificateGenerationInfo certificateGenerationInfo, final CertificateGenerationInfoData certificateGenerationInfoData) {

        if (certificateGenerationInfo.getKeyGenerationAlgorithm() != null) {
            final AlgorithmData keyGenerationAlgorithmData = persistenceManager.findEntity(AlgorithmData.class, certificateGenerationInfo.getKeyGenerationAlgorithm().getId());
            certificateGenerationInfoData.setKeyGenerationAlgorithmData(keyGenerationAlgorithmData);
        }

        if (certificateGenerationInfo.getSignatureAlgorithm() != null) {
            final AlgorithmData signatureAlgorithmData = persistenceManager.findEntity(AlgorithmData.class, certificateGenerationInfo.getSignatureAlgorithm().getId());
            certificateGenerationInfoData.setSignatureAlgorithmData(signatureAlgorithmData);
        }

        if (certificateGenerationInfo.getIssuerSignatureAlgorithm() != null) {
            final AlgorithmData issuerSignatureAlgorithmData = persistenceManager.findEntity(AlgorithmData.class, certificateGenerationInfo.getIssuerSignatureAlgorithm().getId());
            certificateGenerationInfoData.setIssuerSignatureAlgorithmData(issuerSignatureAlgorithmData);
        }

    }

    private void seEntityInfo(final CertificateGenerationInfo certificateGenerationInfo, final CertificateGenerationInfoData certificateGenerationInfoData) throws PersistenceException {

        if (certificateGenerationInfo.getCAEntityInfo() != null) {
            final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificateGenerationInfo.getCAEntityInfo().getName(), Constants.CA_NAME_PATH);
            certificateGenerationInfoData.setcAEntityInfo(caEntityData);
        }
        if (certificateGenerationInfo.getEntityInfo() != null) {
            final EntityData entityData = persistenceManager.findEntityByName(EntityData.class, certificateGenerationInfo.getEntityInfo().getName(), Constants.ENTITY_NAME_PATH);
            certificateGenerationInfoData.setEntityInfo(entityData);
        }
    }

    private Certificate mapToIssuerCertificate(final CertificateData certificateData) {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());

        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setIssuedTime(certificateData.getIssuedTime());
        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }
        certificate.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));
        return certificate;
    }

    public Certificate toCertificateForTDPSInfo(final CertificateData certificateData) throws CertificateException, IOException {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());

        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));

        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }

        if ( certificateData.getIssuerCA() != null) {

            if (certificateData.getIssuerCA().isExternalCA()) {
                final ExtCA extCA = extCAMapper.toAPIFromModel(certificateData.getIssuerCA());
                certificate.setIssuer(extCA.getCertificateAuthority());
            } else {
                final CAEntity caEntity = caEntityMapper.toAPIFromModelForCAName(certificateData.getIssuerCA());
                certificate.setIssuer(caEntity.getCertificateAuthority());
            }
        }

        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        certificate.setX509Certificate(x509Certificate);
        return certificate;

    }

}
