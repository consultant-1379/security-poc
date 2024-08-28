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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

public class CertificateSetUpData {

    private static final String certificate = "Sample bytes";

    /**
     * Prepares {@link CertificateData} to check for equals method.
     * 
     * @return {@link CertificateData} to compare.
     */
    public CertificateData getCertificateForEqual() {
        final CertificateData certificateData = new CertificateData();

        certificateData.setId(1);
        try {
            certificateData.setIssuedTime((new SimpleDateFormat("dd-MM-yyyy")).parse("03-20-2020"));
            certificateData.setNotAfter((new SimpleDateFormat("dd-MM-yyyy")).parse("01-01-2025"));
            certificateData.setNotBefore((new SimpleDateFormat("dd-MM-yyyy")).parse("02-02-2020"));
        } catch (ParseException parseException) {
            parseException.printStackTrace();
        }
        certificateData.setSerialNumber("123");
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setCertificate(certificate.getBytes());
        certificateData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        certificateData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        return certificateData;
    }

    /**
     * Prepares {@link CertificateData} to check for equals method.
     * 
     * @return {@link CertificateData} to compare.
     */
    public CertificateData getCertificateForNotEqual() {

        final CertificateData certificateData = new CertificateData();

        certificateData.setId(1);
        try {
            certificateData.setIssuedTime((new SimpleDateFormat("dd-MM-yyyy")).parse("10-10-2030"));
            certificateData.setNotAfter((new SimpleDateFormat("dd-MM-yyyy")).parse("01-01-2020"));
            certificateData.setNotBefore((new SimpleDateFormat("dd-MM-yyyy")).parse("02-02-2021"));
        } catch (ParseException parseException) {
            parseException.printStackTrace();
        }
        certificateData.setSerialNumber("456");
        certificateData.setStatus(CertificateStatus.EXPIRED);
        certificateData.setCertificate(certificate.getBytes());
        certificateData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        certificateData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        return certificateData;
    }
}
