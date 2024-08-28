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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.CertException;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidDurationFormatException;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

/**
 * This class will convert the CrlGenerationInfo for a CertificateAuthority from JPA to API model and viceversa.
 *
 * @author xananer
 *
 */
public class CRLGenerationInfoMapper {

    private static final String NAME_PATH = "name";
    private static final String TYPE_PATH = "type";
    //Code commented as TORF-66997 is not implemented yet
    //Bug : TORF-209127
   // private static final String SUPPORTED_PATH = "supported";

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper certificateModelMapper;
    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    /**
     * Maps the CRLGenerationInfo API model to its corresponding JPA model
     *
     * @param crlGenerationInfoList
     *            is the list of the CrlGenerationInfo associated with a CertificateAuthority
     * @return will set the value CrlGenerationInfo set to the CertificateAuthority
     * @throws CoreEntityServiceException
     *             thrown, if any database failures occurs in case of CRL operations.
     *
     */
    public Set<CrlGenerationInfoData> fromAPIModel(final List<CrlGenerationInfo> crlGenerationInfoList) throws CoreEntityServiceException {
        final Set<CrlGenerationInfoData> associatedCrl = new HashSet<>();
        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            final CrlGenerationInfoData crlGenerationInfoData = new CrlGenerationInfoData();
            crlGenerationInfoData.setOverlapPeriod(crlGenerationInfo.getOverlapPeriod().toString());
            crlGenerationInfoData.setValidityPeriod(crlGenerationInfo.getValidityPeriod().toString());
            crlGenerationInfoData.setSkewCrlTime(crlGenerationInfo.getSkewCrlTime().toString());
            crlGenerationInfoData.setVersion(crlGenerationInfo.getVersion().value());
            crlGenerationInfoData.setCrlExtensionsJSONData(JsonUtil.getJsonFromObject(crlGenerationInfo.getCrlExtensions()));
            final Set<CertificateData> certificateDatas = new HashSet<>();
            if (crlGenerationInfo.getCaCertificates() != null) {
                for (final Certificate certificate : crlGenerationInfo.getCaCertificates()) {
                    try {
                        certificateDatas.add(certificatePersistenceHelper.getCertificateData(certificate));
                    } catch (final CertException e) {
                        logger.debug("Error while Adding Certificates to the CrlGenerationInfo ", e);
                        logger.info("Error while Adding Certificates to the CrlGenerationInfo");
                    }
                }
            }
            crlGenerationInfoData.setCaCertificate(certificateDatas);
            AlgorithmData algorithmData = null;

            try {
                algorithmData = getSignatureAlgorithmData(crlGenerationInfo.getSignatureAlgorithm().getName());
            } catch (final PersistenceException e) {
                logger.debug("Unable to get the signature Algorithm Data ", e);
                throw new CoreEntityServiceException("Unable to get the signature Algorithm Data");
            }
            crlGenerationInfoData.setSignatureAlgorithm(algorithmData);
            associatedCrl.add(crlGenerationInfoData);
        }
        return associatedCrl;
    }

    /**
     * Maps the CRLGenerationInfo API model to its corresponding JPA model
     *
     * @param crlGenerationInfoDataList
     *            is the list of CrlGenerationInfoData associated with a CertificateAuthorityData
     * @return
     * @throws CertificateException
     * @throws InvalidCRLGenerationInfoException
     *             is thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CrlGenerationInfo> toAPIModel(final Set<CrlGenerationInfoData> crlGenerationInfoDataList) throws CertificateException, InvalidCRLGenerationInfoException {
        final List<CrlGenerationInfo> crlGenerationInfoList = new ArrayList<>();
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
                logger.debug("Exception occurred while converting String Date to duration ", e);
                logger.error("Exception occurred while converting String Date {} to duration - {}", invalidFieldType, e.getMessage());
                throw new InvalidCRLGenerationInfoException("Exception occurred while converting String Date " + invalidFieldType + " to duration - " + e.getMessage());
            }
            crlGenerationInfo.setSignatureAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(crlGenerationInfoData.getSignatureAlgorithm()));
            final int version = crlGenerationInfoData.getVersion();
            crlGenerationInfo.setVersion(CRLVersion.fromValue(version));
            final ArrayList<CertificateData> certificateDataList = new ArrayList<>(crlGenerationInfoData.getCaCertificate());
            final ArrayList<Certificate> certificateList = new ArrayList<>();
            for (final CertificateData certificateData : certificateDataList) {
                certificateList.add(certificateModelMapper.mapToCertificate(certificateData));
            }
            crlGenerationInfo.setCaCertificates(certificateList);
            crlGenerationInfoList.add(crlGenerationInfo);
        }
        return crlGenerationInfoList;
    }

    /**
     * This method returns algorithm if any found in DB with given name, given keysize, type as SIGNATURE_ALGORITHM and supported as true
     *
     * @param name
     *            is the name of the signatureAlgorithm
     * @return AlgorithmData is the Algorithm fetched for the given input set
     * @throws CRLServiceException
     *             thrown, if any database failures occurs in case of CRL operations.
     * @throws PersistenceException
     *             thrown when any internal Database errors occur.
     */
    public AlgorithmData getSignatureAlgorithmData(final String name) throws CRLServiceException, PersistenceException {
        final Map<String, Object> input = new HashMap<>();

        input.put(NAME_PATH, name);
        input.put(TYPE_PATH, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        //Code commented as TORF-66997 is not implemented yet
        //Bug : TORF-209127
       // input.put(SUPPORTED_PATH, true);

        final List<AlgorithmData> algorithmDataList = persistenceManager.findEntitiesByAttributes(AlgorithmData.class, input);

        if (algorithmDataList.size() >= 2 || algorithmDataList.isEmpty()) {
            throw new CRLServiceException("Signature Algorithm Not Found");
        }
        return algorithmDataList.get(0);
    }
}
