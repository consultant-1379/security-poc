/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb

import spock.lang.Unroll

import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionResourceNotFoundException
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException
import java.security.cert.X509Certificate

/**
 * This class covers positive and Negative scenario test cases to retrieves the certificate from TDPS DB based on entityName.
 *
 * @author zkakven
 *
 */

public class TDPSBeanTest extends AbstractBaseSpec {

    @ObjectUnderTest
    TrustDistributionPointServiceBean trustDistributionPointServiceBean

    @Unroll("Retrieving trust certificate data for #entityType and #entityName")
    def "Retrieving trust certificate data for entityType and entityName"() {
        given :"entity type, entityName, issuer name, certificateSerialId and certificateStatus"
        def trustDistributionParameters = new TrustDistributionParameters(entityType:entityType, entityName:entityName, issuerName:issuerName, certificateSerialId:certificateSerialId, certificateStatus:certificateStatus)
        def filePath = FilePath
        setTDPSEntityData(trustDistributionParameters, filePath)
        when: "execute getCertificate method"
        byte[] trustCertificate = trustDistributionPointServiceBean.getCertificate(trustDistributionParameters)
        then:"getCertificate should return trustCertificate"
        X509Certificate certificate = CertificateUtility.getCertificateFromByteArray(trustCertificate)
        String issuer=StringUtility.getCNfromDN(certificate.issuerDN.name)
        issuer == issuerName
        where : "Entity details"
        entityType      |      entityName         |         issuerName         |    certificateSerialId  |  certificateStatus |          FilePath
        'CA_ENTITY'     |     'ENM_NBI_CA'        |  'ENM_Infrastructure_CA'   |     '79944672e936137e'  |      'ACTIVE'      |   '/crt/Certificate.crt'
    }

    @Unroll("Retrieving trust certificate data for invalid #entityType and #entityName")
    def "TrustRetrieving trust certificate data for invalid entityType and entityName"() {
        given :"entity type, entityName, issuer name, certificateSerialId and certificateStatus"
        def filePath = FilePath
        def trustDistributionParameters = new TrustDistributionParameters(entityType:entityType, entityName:entityName, issuerName:issuerName, certificateSerialId:certificateSerialId, certificateStatus:certificateStatus)
        setTDPSEntityData(trustDistributionParameters, filePath)
        when: "execute getCertificate method"
        byte[] trustCertificate = trustDistributionPointServiceBean.getCertificate(trustDistributionParameters)
        then:"getCertificate should throw an exception"
        def error = thrown(ExpectedException)
        where : "Entity details"
        entityType      |     entityName    |     issuerName      | certificateSerialId  |  certificateStatus |         FilePath        |              ExpectedException
        'CA_ENTITY'     |       null        | 'ENM_PKI_Root_CA'   |  '6fc70c3ef195c309'  |      'ACTIVE'      | '/crt/Certificate.crt'  |  TrustDistributionResourceNotFoundException
        'ENTITY'        |     'Test_EE'     |    'NE_OAM_CA'      |  '‎1e3241b2de450740'  |     'INACTIVE'     |           null          |      TrustDistributionServiceException
    }
}