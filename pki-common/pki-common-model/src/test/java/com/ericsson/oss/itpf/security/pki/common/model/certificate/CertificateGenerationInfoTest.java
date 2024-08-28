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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import java.text.ParseException;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmTest;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthorityTest;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfoTest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestTest;
import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CertificateExtensionsSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CertificateGenerationInfoSetUpData;

/**
 * This class is used to run Junits for CertificateGenerationInfo objects in different scenarios
 */
public class CertificateGenerationInfoTest extends EqualsTestCase {

    private static final String EQUAL_SKEW_TIME = "PT1H1M30S";
    private static final String NOT_EQUAL_SKEW_TIME = "PT1H1M30S";
    private static final String EQUAL_VALIDITY = "P360D";
    private static final String NOT_EQUAL_VALIDITY = "P365D";
    private static final String subjectUniqueIdentifierValue = "cert1";
    private static final String issuerUniqueIdentifierValue = "cert2";

    @Override
    protected Object createInstance() throws ParseException, DatatypeConfigurationException {
        return (new CertificateGenerationInfoSetUpData().cAEntityInfo((CertificateAuthority) new CertificateAuthorityTest().createInstance())
                .certificateExtensions(new CertificateExtensionsSetUpData().buildEqualCertificateExtensions())).cSR((CertificateRequest) new CertificateRequestTest().createInstance())
                .entityInfo((EntityInfo) new EntityInfoTest().createInstance()).issuerCA((CertificateAuthority) new CertificateAuthorityTest().createInstance()).issuerUniqueIdentifier(true)
                .keyGenerationAlgorithm((Algorithm) new AlgorithmTest().createNotEqualInstance()).signatureAlgorithm((Algorithm) new AlgorithmTest().createInstance())
                .issuerSignatureAlgorithm((Algorithm) new AlgorithmTest().createInstance()).skewCertificateTime(DatatypeFactory.newInstance().newDuration(EQUAL_SKEW_TIME))
                .subjectUniqueIdentifier(true).requestType(RequestType.REKEY).validity(DatatypeFactory.newInstance().newDuration(EQUAL_VALIDITY)).version(CertificateVersion.V3)
                .subjectUniqueIdentifierValue(subjectUniqueIdentifierValue).issuerUniqueIdentifierValue(issuerUniqueIdentifierValue).certificate((Certificate) new CertificateTest().createInstance())
                .build();
    }

    @Override
    protected Object createNotEqualInstance() throws ParseException, DatatypeConfigurationException {
        return (new CertificateGenerationInfoSetUpData().cAEntityInfo((CertificateAuthority) new CertificateAuthorityTest().createNotEqualInstance())
                .certificateExtensions(new CertificateExtensionsSetUpData().buildNotEqualCertificateExtensions())).cSR((CertificateRequest) new CertificateRequestTest().createNotEqualInstance())
                .entityInfo((EntityInfo) new EntityInfoTest().createNotEqualInstance()).issuerCA((CertificateAuthority) new CertificateAuthorityTest().createNotEqualInstance())
                .issuerUniqueIdentifier(true).keyGenerationAlgorithm((Algorithm) new AlgorithmTest().createNotEqualInstance())
                .signatureAlgorithm((Algorithm) new AlgorithmTest().createNotEqualInstance()).issuerSignatureAlgorithm((Algorithm) new AlgorithmTest().createNotEqualInstance())
                .skewCertificateTime(DatatypeFactory.newInstance().newDuration(NOT_EQUAL_SKEW_TIME)).subjectUniqueIdentifier(true).requestType(RequestType.REKEY)
                .validity(DatatypeFactory.newInstance().newDuration(NOT_EQUAL_VALIDITY)).version(CertificateVersion.V3).subjectUniqueIdentifierValue(subjectUniqueIdentifierValue)
                .issuerUniqueIdentifierValue(issuerUniqueIdentifierValue).certificate((Certificate) new CertificateTest().createNotEqualInstance()).build();
    }

}
