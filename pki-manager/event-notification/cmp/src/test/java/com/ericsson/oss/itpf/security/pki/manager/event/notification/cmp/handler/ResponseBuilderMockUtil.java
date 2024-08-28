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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

public class ResponseBuilderMockUtil {

    public static CertificateRequest generateCSR(final PKIBody body) throws Exception {
        CRMFRequestHolder crmfRequestHolder = getCRMFRequestHolder(body);
        CertificateRequest csr = new CertificateRequest();
        csr.setCertificateRequestHolder(crmfRequestHolder);
        return csr;
    }

    public static CRMFRequestHolder getCRMFRequestHolder(final PKIBody body) throws Exception {
        CertReqMessages certReqMessages = (CertReqMessages) body.getContent();
        CertReqMsg certReqMsg = certReqMessages.toCertReqMsgArray()[0];
        CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(certReqMsg);
        CRMFRequestHolder crmfRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        return crmfRequestHolder;

    }

    public static Certificate getUSerCertificate(CertDataHolder certDataHolder) throws Exception {
        X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certDataHolder.getCert());
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
        Certificate userCertificate = new Certificate();
        userCertificate.setX509Certificate(certificate);

        return userCertificate;
    }

    public static List<Certificate> getTrsutedCertificates(Certificate userCertificate) {
        List<Certificate> trustedCertificates = new ArrayList<Certificate>();
        trustedCertificates.add(userCertificate);
        return trustedCertificates;
    }

    public static CertificateChain getCertificateChain(List<Certificate> trustedCertificates) {
        CertificateChain certChain = new CertificateChain();
        certChain.setCertificateChain(trustedCertificates);

        return certChain;

    }

    public static List<X509Certificate> getX509TrsutedCertificates(Certificate userCertificate) {
        List<X509Certificate> trustedCertificates = new ArrayList<X509Certificate>();
        trustedCertificates.add(userCertificate.getX509Certificate());
        return trustedCertificates;
    }

}
