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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidDurationFormatException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class will convert a CrlGenerationInfo from a JPA to API model and viceversa.
 *
 * @author xananer
 *
 */
public class CRLGenerationInfoMapper {

    private static final String NAME_PATH = "name";
    private static final String TYPE_PATH = "type";
    private static final String SUPPORTED_PATH = "supported";

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper certificateModelMapper;

    /**
     * Maps the CRLGenerationInfo API model to its corresponding JPA model
     *
     * @param crlGenerationInfoList
     *            List of crlGenerationInfo Objects
     * @return Set<CrlGenerationInfoData>
     * @throws CRLServiceException
     *             thrown when any internal Database errors occur in case CRL operations.
     */
    public Set<CrlGenerationInfoData> toModelFromAPI(final List<CrlGenerationInfo> crlGenerationInfoList) throws CRLServiceException {
        final Set<CrlGenerationInfoData> associatedCrl = new HashSet<CrlGenerationInfoData>();
        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            final CrlGenerationInfoData crlGenerationInfoData = new CrlGenerationInfoData();
            crlGenerationInfoData.setId(crlGenerationInfo.getId());
            crlGenerationInfoData.setOverlapPeriod(crlGenerationInfo.getOverlapPeriod().toString());
            crlGenerationInfoData.setValidityPeriod(crlGenerationInfo.getValidityPeriod().toString());
            crlGenerationInfoData.setSkewCrlTime(crlGenerationInfo.getSkewCrlTime().toString());
            crlGenerationInfoData.setVersion(crlGenerationInfo.getVersion().value());
            crlGenerationInfoData.setCrlExtensionsJSONData(JsonUtil.getJsonFromObject(crlGenerationInfo.getCrlExtensions()));
            AlgorithmData algorithmData;
            algorithmData = getSignatureAlgorithmData(crlGenerationInfo.getSignatureAlgorithm().getName());

            crlGenerationInfoData.setSignatureAlgorithmId(algorithmData);

            final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
            if (crlGenerationInfo.getCaCertificates() != null) {
                for (final Certificate certificate : crlGenerationInfo.getCaCertificates()) {
                    certificateDatas.add(getCertificateData(certificate));
                }
            }
            associatedCrl.add(crlGenerationInfoData);
        }
        return associatedCrl;
    }

    /**
     * This method will get the CertificateData JPA object from database when a Certificate object is passed
     *
     * @param certificate
     *            is the Certificate Class contain the certificate details
     *
     * @return CertificateData is the CertificateData Class contain the certificate details
     *
     */
    public CertificateData getCertificateData(final Certificate certificate) {
        CertificateData certificateData = null;
        try {
            certificateData = persistenceManager.findEntity(CertificateData.class, certificate.getId());
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while fetching certificate ", persistenceException);
            logger.error("Error occured while fetching certificate" + persistenceException.getMessage());

            // unnecessary throws and ignoring in catch code is removed.
        }
        return certificateData;
    }

    /**
     * Maps the CRLGenerationInfo JPA model to its corresponding API model
     *
     * @param crlGenerationInfoDataList
     *            List of crlGenerationInfo Objects
     * @return List<CrlGenerationInfo>
     * @throws CertificateException
     * @throws InvalidCRLGenerationInfoException
     *             is thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     * @throws IOException
     *             thrown when the encoding of certificate from db has failed.
     */
    public List<CrlGenerationInfo> toAPIFromModel(final Set<CrlGenerationInfoData> crlGenerationInfoDataList) throws CertificateException, InvalidCRLGenerationInfoException, IOException {
        final List<CrlGenerationInfo> crlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        for (final CrlGenerationInfoData crlGenerationInfoData : crlGenerationInfoDataList) {
            final CrlGenerationInfo crlGenerationInfo = new CrlGenerationInfo();
            crlGenerationInfo.setId(crlGenerationInfoData.getId());
            crlGenerationInfo.setCrlExtensions(JsonUtil.getObjectFromJson(CrlExtensions.class, crlGenerationInfoData.getCrlExtensionsJSONData()));
            String invalidFieldType = null;
            try {
                invalidFieldType = "OverlapPeriod";
                crlGenerationInfo.setOverlapPeriod(DateUtility.convertStringToDuration(crlGenerationInfoData.getOverlapPeriod()));
                invalidFieldType = "SkewCrlTime";
                crlGenerationInfo.setSkewCrlTime(DateUtility.convertStringToDuration(crlGenerationInfoData.getSkewCrlTime()));
                invalidFieldType = "ValidityPeriod";
                crlGenerationInfo.setValidityPeriod(DateUtility.convertStringToDuration(crlGenerationInfoData.getValidityPeriod()));
            } catch (final InvalidDurationFormatException e) {
                logger.error("Exception occurred while converting String Date {} to duration - {}", invalidFieldType, e.getMessage());
                throw new InvalidCRLGenerationInfoException("Exception occurred while converting String Date " + invalidFieldType + " to duration - " + e.getMessage(), e);
            }
            crlGenerationInfo.setSignatureAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(crlGenerationInfoData.getSignatureAlgorithm()));
            final int verison = crlGenerationInfoData.getVersion();
            crlGenerationInfo.setVersion(CRLVersion.fromValue(verison));
            crlGenerationInfo.setCaCertificates(toCertificate(new ArrayList<CertificateData>(crlGenerationInfoData.getCaCertificate())));
            crlGenerationInfoList.add(crlGenerationInfo);
        }
        return crlGenerationInfoList;
    }

    /**
     * Maps the CRLGenerationInfo JPA model to its corresponding API model with the fields required as per the EntitiesSchema.xsd
     *
     * @param crlGenerationInfoDataList
     *            List of crlGenerationInfo Objects
     * @return List<CrlGenerationInfo>
     * @throws CertificateException
     * @throws InvalidCRLGenerationInfoException
     *             is thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     * @throws IOException
     *             thrown when the encoding of certificate from db has failed.
     */
    public List<CrlGenerationInfo> toAPIFromModelForImport(final Set<CrlGenerationInfoData> crlGenerationInfoDataList) throws CertificateException, InvalidCRLGenerationInfoException, IOException {
        final List<CrlGenerationInfo> crlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        for (final CrlGenerationInfoData crlGenerationInfoData : crlGenerationInfoDataList) {
            final CrlGenerationInfo crlGenerationInfo = new CrlGenerationInfo();
            crlGenerationInfo.setId(crlGenerationInfoData.getId());
            crlGenerationInfo.setCrlExtensions(JsonUtil.getObjectFromJson(CrlExtensions.class, crlGenerationInfoData.getCrlExtensionsJSONData()));
            String invalidFieldType = null;
            try {
                invalidFieldType = "OverlapPeriod";
                crlGenerationInfo.setOverlapPeriod(DateUtility.convertStringToDuration(crlGenerationInfoData.getOverlapPeriod()));
                invalidFieldType = "SkewCrlTime";
                crlGenerationInfo.setSkewCrlTime(DateUtility.convertStringToDuration(crlGenerationInfoData.getSkewCrlTime()));
                invalidFieldType = "ValidityPeriod";
                crlGenerationInfo.setValidityPeriod(DateUtility.convertStringToDuration(crlGenerationInfoData.getValidityPeriod()));
            } catch (final InvalidDurationFormatException e) {
                logger.error("Exception occurred while converting String Date {} to duration - {}", invalidFieldType, e.getMessage());
                throw new InvalidCRLGenerationInfoException("Exception occurred while converting String Date " + invalidFieldType + " to duration - " + e.getMessage(), e);
            }
            crlGenerationInfo.setSignatureAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmDataForImport(crlGenerationInfoData.getSignatureAlgorithm()));
            final int verison = crlGenerationInfoData.getVersion();
            crlGenerationInfo.setVersion(CRLVersion.fromValue(verison));
            crlGenerationInfoList.add(crlGenerationInfo);
        }
        return crlGenerationInfoList;
    }

    /**
     * Converts the Certificate JPA model to corresponding API Model
     *
     * @param certificateDataList
     *            List of certificateData Objects.
     * @return List<Certificate>
     * @throws CertificateException
     *             thrown when the encoding of certificate from db has failed.
     * @throws IOException
     *             thrown when the encoding of certificate from db has failed.
     */
    private List<Certificate> toCertificate(final List<CertificateData> certificateDataList) throws CertificateException, IOException {
        final List<Certificate> certificateList = new ArrayList<Certificate>();
        for (final CertificateData certificateData : certificateDataList) {
            final Certificate certificate = new Certificate();
            certificate.setId(certificateData.getId());
            certificate.setSerialNumber(certificateData.getSerialNumber());
            certificate.setIssuedTime(certificateData.getIssuedTime());
            certificate.setNotAfter(certificateData.getNotAfter());
            certificate.setNotBefore(certificateData.getNotBefore());
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
            final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
            certificate.setX509Certificate(x509Certificate);
            certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
            certificateList.add(certificate);
        }
        return certificateList;
    }

    /**
     * This method returns algorithm if any found in DB with given name, given keysize, type as SIGNATURE_ALGORITHM and supported as true
     *
     * @param name
     *            Algorithm Name.
     * @return AlgorithmData
     * @throws CRLServiceException
     *             thrown when any internal Database errors occur.
     */
    public AlgorithmData getSignatureAlgorithmData(final String name) throws CRLServiceException {
        final Map<String, Object> input = new HashMap<String, Object>();
        final Boolean value = Boolean.valueOf(true);
        input.put(NAME_PATH, name);
        input.put(TYPE_PATH, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put(SUPPORTED_PATH, value);

        AlgorithmData algorithmData = null;
        try {
            algorithmData = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException e) {
            logger.error("Internal error while retrieving CAs in DB {}", e.getMessage());
            throw new CRLServiceException("Occured in retrieving CAs", e);
        }
        return algorithmData;
    }
}
