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
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

import java.util.ArrayList;

import org.bouncycastle.asn1.x500.style.X500NameTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class is an implementation of building certificate enrollment status
 *
 * @author xgvgvgv
 *
 */
public class CertificateEnrollmentStatusBuilder {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateEnrollmentStatusBuilder.class);

    /**
     * This method is for building certificate enrollment status
     *
     * @param subjectName
     *            Subject Name in the Certificate Request
     * 
     * @param IssuerName
     *            Name of the issuer
     *
     * @param certificateEnrollmentStatusType
     *            type of certificate enrollment status
     *
     * @return certificateEnrollmentStatus
     * 
     */
    public CertificateEnrollmentStatus build(final String subjectName, final String issuerName, final CertificateEnrollmentStatusType certificateEnrollmentStatusType) {

        LOGGER.debug("Building Certificate Enrollment status event for Certificate Request with Subject {} and Issuer {} with status: {}", subjectName, issuerName, certificateEnrollmentStatusType);
        CertificateEnrollmentStatus certificateEnrollmentStatus = null;
        try {
            if (subjectName != null && !subjectName.isEmpty() && issuerName != null && !issuerName.isEmpty()) {
                certificateEnrollmentStatus = prepareCertEnrollNotificationStatus(subjectName, issuerName, certificateEnrollmentStatusType);
            } else {
                LOGGER.info("Either Subject Name : {} or Issuer Name : {} is null or empty", subjectName, issuerName);
            }
        } catch (Exception e) {
            LOGGER.error("Exception occured while building Certificate Enrollment Status", e);
        }
        return certificateEnrollmentStatus;
    }

    private static CertificateEnrollmentStatus prepareCertEnrollNotificationStatus(final String subjectName, final String issuerName,
            final CertificateEnrollmentStatusType certificateEnrollmentStatusType) {
        CertificateEnrollmentStatus certificateEnrollmentStatus = null;
        final String[] subjectDetails = splitDNs(subjectName);
        for (final String subjectData : subjectDetails) {
            if (subjectData.contains(Constants.SENDER_DETAILS)) {
                certificateEnrollmentStatus = prepareCertEnrollStatus(subjectData, issuerName, certificateEnrollmentStatusType);
                break;
            } else {
                LOGGER.info("Common Name is not present in the Subject name : {}", subjectData);
            }
        }
        return certificateEnrollmentStatus;
    }

    private static CertificateEnrollmentStatus prepareCertEnrollStatus(final String commonName, final String issuerName, final CertificateEnrollmentStatusType certificateEnrollmentStatusType) {
        CertificateEnrollmentStatus certificateEnrollmentStatus = null;
        final String nodeInfoDetails = commonName.substring(3);
        if (commonName.contains(Constants.HYPHEN_TOKEN)) {
            /**
             * This Logic is used to extract nodeName and certificateType from commonName. Example : Sender name= CN=LTE02ERBS00002-oam,C=SE,O=ERICSSON,OU=BUCI DUAC NAM.From Sender name we are
             * splitting common name as CN=LTE02ERBS00002-oam.From common name we are extracting node name and certificate type i.e., nodeName = LTE02ERBS00002, certificateType = oam.
             */
            String nodeName = null;
            String certificateType = null;
            if (nodeInfoDetails != null) {
                final int hyphenIndex = nodeInfoDetails.lastIndexOf(Constants.HYPHEN_TOKEN);
                nodeName = nodeInfoDetails.substring(0, hyphenIndex);
                certificateType = buildCertificateType(nodeName, nodeInfoDetails.substring(hyphenIndex + 1));
            }

            if (nodeName != null && !nodeName.isEmpty() && certificateType != null && certificateEnrollmentStatusType != null) {
                certificateEnrollmentStatus = prepareCertificateEnrollmentStatus(nodeName, issuerName, certificateType, certificateEnrollmentStatusType);
            }
        } else {
            certificateEnrollmentStatus = prepareCertificateEnrollmentStatus(commonName, issuerName, CertificateType.UNKNOWN.toString(), certificateEnrollmentStatusType);
        }
        return certificateEnrollmentStatus;
    }

    private static CertificateEnrollmentStatus prepareCertificateEnrollmentStatus(final String commonName, final String issuerName, final String certificateType,
            final CertificateEnrollmentStatusType certificateEnrollmentStatusType) {
        final CertificateEnrollmentStatus certificateEnrollmentStatus = new CertificateEnrollmentStatus();
        certificateEnrollmentStatus.setNodeName(commonName);
        certificateEnrollmentStatus.setIssuerName(issuerName);
        certificateEnrollmentStatus.setCertificateType(CertificateType.valueOf(certificateType));
        certificateEnrollmentStatus.setCertificateEnrollmentStatusType(certificateEnrollmentStatusType);
        return certificateEnrollmentStatus;
    }

    private static String buildCertificateType(final String commonName, final String certificateType) {
        switch (certificateType.toLowerCase()) {
        case Constants.CERTIFICATE_TYPE_OAM:
            return CertificateType.OAM.toString();
        case Constants.CERTIFICATE_TYPE_IPSEC:
            return CertificateType.IPSEC.toString();
        default:
            LOGGER.info("Certificate type cannot be found from the CN, so UNKNOWN notification is being sent: {} for common name: {}", certificateType, commonName);
            return CertificateType.UNKNOWN.toString();
        }
    }

      /**
     * This method is for spliting DNs
     *
     * @param subjectDN
     *            DN  in the Certificate
     * @return Array of RDN names
     *
     */
    public static String[] splitDNs(String subjectDN) {
        X500NameTokenizer x500Tokenizer= new X500NameTokenizer(subjectDN,',');
        ArrayList<String> rdnNames= new ArrayList<>();
        while (x500Tokenizer.hasMoreTokens()) {
            rdnNames.add(x500Tokenizer.nextToken());
        }
        return rdnNames.toArray(new String[rdnNames.size()]);
    }
}