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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;

public class CertificateGenerationInfoParser {

    @Inject
    DateUtil dateUtil;

    @Inject
    Logger logger;

    /**
     * Extracts issuerDN from {@link CertificateGenerationInfo}
     * 
     * @param certificateGenerationInfo
     * @return issuerDN extracted from certificateGenerationInfo
     */
    public String getIssuerDNFromCertGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo) {

        String subject = null;
        if (certificateGenerationInfo.getIssuerCA() == null) {
            subject = certificateGenerationInfo.getCAEntityInfo().getSubject().toASN1String();
        } else {
            if (certificateGenerationInfo.getIssuerCA().getActiveCertificate() == null) {
                subject = certificateGenerationInfo.getIssuerCA().getSubject().toASN1String();
            } else {
                subject = certificateGenerationInfo.getIssuerCA().getActiveCertificate().getSubject().toASN1String();
            }
        }
        return subject;
    }

    /**
     * Extracts subject from {@link CertificateGenerationInfo}
     * 
     * @param certificateGenerationInfo
     * @return subjectDN extracted from certificateGenerationInfo
     */
    public String getSubjectDNFromCertGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo) {

        String subject = null;
        if (certificateGenerationInfo.getEntityInfo() != null) {
            subject = certificateGenerationInfo.getEntityInfo().getSubject().toASN1String();
        } else {
            subject = certificateGenerationInfo.getCAEntityInfo().getSubject().toASN1String();
        }
        return subject;
    }

    /**
     * Extracts subject from {@link CertificateGenerationInfo}
     * 
     * @param certificateGenerationInfo
     * @return subjectAltName extracted from certificateGenerationInfo
     */
    public SubjectAltName getSubjectAltNameFromCertGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo) {

        SubjectAltName subjectAltName = null;
        if (certificateGenerationInfo.getEntityInfo() != null) {
            subjectAltName = certificateGenerationInfo.getEntityInfo().getSubjectAltName();
        } else if (certificateGenerationInfo.getCAEntityInfo() != null) {
            subjectAltName = certificateGenerationInfo.getCAEntityInfo().getSubjectAltName();
        }
        return subjectAltName;
    }

}
