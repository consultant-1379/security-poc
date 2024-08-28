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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data;

import java.io.IOException;
import java.security.*;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

public class CertificateGenerationInfoSetUPData {

    private static final String EQUAL_VALIDITY = "PT1H1M30S";

    private static SetUPData setUPData = new SetUPData();
    private static EntitySetUPData entitySetUPData = new EntitySetUPData();
    private static SubjectSetUPData subjectData = new SubjectSetUPData();
    private static PKCS10CertificationRequestSetUPData pkcs10CertificationRequestSetUPData = new PKCS10CertificationRequestSetUPData();

    public CertificateGenerationInfo getCertificateGenerationInfo_CAEntity() throws DatatypeConfigurationException, InvalidKeyException, NoSuchAlgorithmException, SignatureException,
            NoSuchProviderException, OperatorCreationException, IOException {

        final CertificateGenerationInfo certificateGenerationInfo = getCertificateGenerationInfo();

        final Subject subject = subjectData.getSubject(SetUPData.SUB_CA_NAME);
        certificateGenerationInfo.setCAEntityInfo(setUPData.getCertificateAuthority(SetUPData.SUB_CA_NAME, subject, true));

        return certificateGenerationInfo;

    }

    public CertificateGenerationInfo getCertificateGenerationInfo_Entity() throws DatatypeConfigurationException, InvalidKeyException, NoSuchAlgorithmException, SignatureException,
            NoSuchProviderException, OperatorCreationException, IOException {

        final CertificateGenerationInfo certificateGenerationInfo = getCertificateGenerationInfo();

        final Subject subject = subjectData.getSubject(SetUPData.ENTITY_NAME);
        certificateGenerationInfo.setCAEntityInfo(setUPData.getCertificateAuthority(SetUPData.ENTITY_NAME, subject, true));

        return certificateGenerationInfo;

    }

    private CertificateGenerationInfo getCertificateGenerationInfo() throws DatatypeConfigurationException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
            OperatorCreationException, IOException {

        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();

        certificateGenerationInfo.setId(1);
        certificateGenerationInfo.setVersion(CertificateVersion.V3);
        certificateGenerationInfo.setSubjectUniqueIdentifier(true);
        certificateGenerationInfo.setIssuerUniqueIdentifier(true);
        certificateGenerationInfo.setSubjectUniqueIdentifier(true);
        certificateGenerationInfo.setValidity(DatatypeFactory.newInstance().newDuration(EQUAL_VALIDITY));
        certificateGenerationInfo.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));
        certificateGenerationInfo.setSignatureAlgorithm(setUPData.getSignatureAlgorithm("sha1withrsa"));

        certificateGenerationInfo.setIssuerCA(entitySetUPData.getRootCAEntity().getCertificateAuthority());

        final PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestSetUPData.generatePKCS10Requestwithattributes();
        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);
        certificateGenerationInfo.setCertificateRequest(certificateRequest);

        certificateGenerationInfo.setCertificateExtensions(entitySetUPData.getCertificateExtensions());

        return certificateGenerationInfo;

    }
}
