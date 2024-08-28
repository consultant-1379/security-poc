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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data;

/**
 *  SetUp Class for CrlGenerationInfo. 
 */

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

import javax.xml.datatype.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

public class CrlGenerationInfoSetUpData {

    private static final long id = 100657;
    private static Duration duration;
    private static final String overlapPeriod = "PT1H1M30S";
    private static final String skewCrlTime = "PT1H1M30S";
    private static final String validityPeriod = "P2Y";
    private static final int version = 2;
    private static final String algorithm = "RSA";
    private static final String CERTIFICATE_TYPE = "X.509";
    private static Set<CertificateData> certificateData = new HashSet<CertificateData>();
    private static AlgorithmData signatureAlgorithmData = new AlgorithmData();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method to set data to CrlGenerationInfo.
     * 
     * @return CrlGenerationInfo
     */
    public static CrlGenerationInfo getCrlGenerationInfo() {

        try {
            duration = DatatypeFactory.newInstance().newDuration("P42D");
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }
        final CrlGenerationInfo crlGenerationInfo = new CrlGenerationInfo();
        List<Certificate> caCertificates = new ArrayList<Certificate>();
        caCertificates.add(getCertificate());
        crlGenerationInfo.setCaCertificates(caCertificates);
        CrlExtensions crlExtensions = new CrlExtensions();
        crlGenerationInfo.setCrlExtensions(crlExtensions);
        crlGenerationInfo.setId(id);
        crlGenerationInfo.setOverlapPeriod(duration);
        Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setName(algorithm);
        crlGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        crlGenerationInfo.setSkewCrlTime(duration);
        crlGenerationInfo.setValidityPeriod(duration);
        crlGenerationInfo.setVersion(CRLVersion.V2);
        return crlGenerationInfo;

    }

    /**
     * Method to set data to CrlGenerationInfoData.
     * 
     * @return CrlGenerationInfoData
     */
    public static CrlGenerationInfoData getCrlGenerationInfoData() {
        final CrlGenerationInfoData crlGenerationInfoData = new CrlGenerationInfoData();
        crlGenerationInfoData.setCaCertificate(certificateData);
        crlGenerationInfoData.setCrlExtensionsJSONData("{}");
        crlGenerationInfoData.setId(id);
        crlGenerationInfoData.setOverlapPeriod(overlapPeriod);
        crlGenerationInfoData.setSignatureAlgorithmId(signatureAlgorithmData);
        crlGenerationInfoData.setSkewCrlTime(skewCrlTime);
        crlGenerationInfoData.setValidityPeriod(validityPeriod);
        crlGenerationInfoData.setVersion(version);
        return crlGenerationInfoData;

    }

    /**
     * Method to set data to CrlGenerationInfoDataForNotEqualcase.
     * 
     * @return CrlGenerationInfoDatas
     */

    public static CrlGenerationInfoData getCrlGenerationInfoDataForNotEqual() {
        final CrlGenerationInfoData crlGenerationInfoData = new CrlGenerationInfoData();
        crlGenerationInfoData.setCaCertificate(certificateData);
        crlGenerationInfoData.setCrlExtensionsJSONData("{}");
        crlGenerationInfoData.setId(2);
        crlGenerationInfoData.setOverlapPeriod("PT2H2M30S");
        crlGenerationInfoData.setSignatureAlgorithmId(signatureAlgorithmData);
        crlGenerationInfoData.setSkewCrlTime("PT2H2M30S");
        crlGenerationInfoData.setValidityPeriod("P2Y");
        crlGenerationInfoData.setVersion(345);
        return crlGenerationInfoData;

    }

    /**
     * Method to set data to CrlCertificateDataSet.
     * 
     * @return Set<CertificateData>
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public static Set<CertificateData> getCrlCertificateDataSet() throws CertificateEncodingException, CertificateException, IOException {
        Set<CertificateData> caCertificate = new HashSet<CertificateData>();
        caCertificate.add(getCertificateData());
        return caCertificate;

    }

    /**
     * Method to set data to CertificateData.
     * 
     * @return CertificateData
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public static CertificateData getCertificateData() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateData certificateData = new CertificateData();
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificateData.setCertificate(getX509Certificate("src/test/resources/MyRoot.crt").getEncoded());
        certificateData.setId(123);
        certificateData.setIssuedTime(new Date());
        certificateData.setIssuerCA(null);
        return certificateData;
    }

    /**
     * Method to set data to Certificate.
     * 
     * @return Certificate
     */
    public static Certificate getCertificate() {
        final Certificate certificate = new Certificate();
        certificate.setId(1);
        certificate.setIssuedTime(new Date());
        return certificate;
    }

    /**
     * Method to set data to X509Certificate.
     * 
     * @return X509Certificate.
     */
    public static X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fin);
        return certificate;
    }

    /**
     * Method to Set Values to input.
     * 
     * @return input.
     */
    public static Map<String, Object> getInput() {
        final Map<String, Object> input = new HashMap<String, Object>();
        final String NAME_PATH = "name";
        final String TYPE_PATH = "type";
        final String SUPPORTED_PATH = "supported";
        input.put(NAME_PATH, "SignatureAlgorithm");
        input.put(TYPE_PATH, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put(SUPPORTED_PATH, true);
        return input;
    }

}
