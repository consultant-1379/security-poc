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
package com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.impl;

import spock.lang.Unroll
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData

/**
 * This class covers positive and negative scenario test cases which is used to publish, unpublish and list the certificates from TDPS db.
 *
 * @author xvadyas
 *
 */

public class TDPSLocalServiceBeanTest extends AbstractBaseSpec {

    @ObjectUnderTest
    TDPSLocalServiceBean tdpsLocalServiceBean


    @Unroll("Publish and unpublish certificates from TDPS database for EntityName #entityName and EntityType #tdpsEntityType")
    def "Publish and Unpublish Certificates using valid TDPSCertificateInfo"() {
        given :"entityName, issuerName, tdpsEntityType, serialNumber and tdpsCertificateStatusType"
        def tdpsCertificateInfo = new TDPSCertificateInfo(entityName:entityName, issuerName:issuerName, tdpsEntityType:tdpsEntityType, serialNumber:serialNumber, tdpsCertificateStatusType:tdpsCertificateStatusType)
        setTDPSEntityData(tdpsCertificateInfo,FilePath)
        when: "execute publishTDPSCertificates method"
        tdpsLocalServiceBean.publishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert publish response"
        when: "execute unPublishTDPSCertificates method"
        tdpsLocalServiceBean.unPublishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert unpublish response"
        where : "Entity details"
        entityName      |       issuerName         |    tdpsEntityType  |     serialNumber     |   tdpsCertificateStatusType    |       FilePath
        'ENM_NBI_CA'    |  'ENM_Infrastructure_CA' |    'CA_ENTITY'     |  '79944672e936137e'  |           'ACTIVE'             |'/cert/Certificate.crt'
        'Test_EE'       |       'NE_OAM_CA'        |      'ENTITY'      |  '1e3241b2de450740'  |          'INACTIVE'            | '/cert/EndEntity.crt'
    }
    @Unroll("Publish certificates to TDPS database for EntityName #entityName when it is not found in DB")
    def "Publishing TDPSCertificates using TDPSCertificateInfo"() {
        given :"entityName, issuerName, tdpsEntityType, serialNumber and tdpsCertificateStatusType"
        def tdpsCertificateInfo = new TDPSCertificateInfo(entityName:entityName, issuerName:issuerName, tdpsEntityType:tdpsEntityType, serialNumber:serialNumber, tdpsCertificateStatusType:tdpsCertificateStatusType)
        setTDPSEntityData(tdpsCertificateInfo,FilePath)
        when: "execute publishTDPSCertificates method"
        tdpsLocalServiceBean.publishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert publish response"
        where : "Entity details"
        entityName      |       issuerName         |    tdpsEntityType  |     serialNumber     |   tdpsCertificateStatusType    |       FilePath
        'ENM_NBI_CA'    |  'ENM_Infrastructure_CA' |    'CA_ENTITY'     |  '79944672e936137e'  |           'ACTIVE'             | '/cert/EndEntity.crt'
        'Test_EE'       |       'NE_OAM_CA'        |      'ENTITY'      |  '1e3241b2de450740'  |          'INACTIVE'            |'/cert/Certificate.crt'
    }
    @Unroll("Unpublish certificates from TDPS database for EntityName #entityName when certificate is not found in the database")
    def "Unpublishing TDPSCertificates using TDPSCertificateInfo"() {
        given :"entityName, issuerName, tdpsEntityType, serialNumber and tdpsCertificateStatusType"
        def tdpsCertificateInfo = new TDPSCertificateInfo(entityName:entityName, issuerName:issuerName, tdpsEntityType:tdpsEntityType, serialNumber:serialNumber, tdpsCertificateStatusType:tdpsCertificateStatusType)
        setTDPSEntityData(tdpsCertificateInfo,FilePath)
        when: "execute unPublishTDPSCertificates method"
        tdpsLocalServiceBean.unPublishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert unpublish response"
        def error = thrown(ExpectedException)
        where : "Entity details"
        entityName      |       issuerName         |    tdpsEntityType  |     serialNumber     |   tdpsCertificateStatusType    |       FilePath        |           ExpectedException
        'ENM_NBI_CA'    |  'ENM_Infrastructure_CA' |    'CA_ENTITY'     |  '79944672e936137e'  |           'ACTIVE'             | '/cert/EndEntity.crt' |      CertificateNotFoundException
        'Test_EE'       |       'NE_OAM_CA'        |      'ENTITY'      |  '1e3241b2de450740'  |          'INACTIVE'            |'/cert/Certificate.crt'|      CertificateNotFoundException
    }
    @Unroll("Error occured during DB operations while publish and unpublish certificates from TDPS database for EntityName #entityName and EntityType #tdpsEntityType")
    def "Exception occured during publish and unpublish certificates while persists or merge entity into DB"() {
        given :"entityName, issuerName, tdpsEntityType, serialNumber and tdpsCertificateStatusType"
        def tdpsCertificateInfo = new TDPSCertificateInfo(entityName:entityName, issuerName:issuerName, tdpsEntityType:tdpsEntityType, serialNumber:serialNumber, tdpsCertificateStatusType:tdpsCertificateStatusType)
        setTDPSEntityData(tdpsCertificateInfo, FilePath)
        when: "execute publishTDPSCertificates method"
        tdpsLocalServiceBean.publishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert publish response"
        def error_publish = thrown(ExpectedException)
        when: "execute unPublishTDPSCertificates method"
        tdpsLocalServiceBean.unPublishTDPSCertificates(tdpsCertificateInfo)
        then: "Assert unpublish response"
        def error_unpublish = thrown(ExpectedException)
        where : "Entity details"
        entityName    |       issuerName         |   tdpsEntityType   |     serialNumber     |   tdpsCertificateStatusType  |       FilePath        |               ExpectedException
        null          |  'ENM_Infrastructure_CA' |    'CA_ENTITY'     |  '79944672e936137e'  |         'ACTIVE'             |'/cert/Certificate.crt'|       TrustDistributionServiceException
        null          |  'ENM_Infrastructure_CA' |    'CA_ENTITY'     |    '79944672e936137e'|         'ACTIVE'             | '/cert/EndEntity.crt' |       TrustDistributionServiceException
    }
    @Unroll("List the TDPSCertificates which are published in TDPS database with EntityName #EntityName")
    def "List the TDPSCertificates"() {
        given :"EntitiesList"
        def TDPSEntity entityType = EntityType
        def TDPSCertificateStatus tdpsCertificateStatus = TdpsCertificateStatus
        setTDPSEntityData_List(EntityName, entityType, IssuerName, SerialNo, tdpsCertificateStatus, FilePath)
        when: "execute persistTdpsEntities method"
        tdpsLocalServiceBean.persistTdpsEntities(tdpsEntityDataList)
        then: "Assert response"
        where : "Entity details"
        EntityName      |    EntityType    |     SerialNo     |        IssuerName          |  TdpsCertificateStatus     |        FilePath
        'ENM_NBI_CA'    |   'CA_ENTITY'    |'79944672e936137e'| 'ENM_Infrastructure_CA'    |        'ACTIVE'            |'/cert/Certificate.crt'
        'Test_EE'       |     'ENTITY'     |'1e3241b2de450740'|        'NE_OAM_CA'         |       'INACTIVE'           |'/cert/Certificate.crt'
        null            |   'CA_ENTITY'    |'79944672e936137e'| 'ENM_Infrastructure_CA'    |        'ACTIVE'            |'/cert/Certificate.crt'
    }
    @Unroll("Error occured during DB operation while getting the list of TDPSCertificates with EntityName #EntityName ")
    def "Exception occured during list certificates while persists or merge entity into DB"(){
        given :"EntitiesList"
        def TDPSEntity entityType = EntityType
        def TDPSCertificateStatus tdpsCertificateStatus = TdpsCertificateStatus
        setInvalidTDPSEntityData_List(EntityName, entityType, IssuerName, SerialNo, tdpsCertificateStatus, FilePath)
        when: "execute persistTdpsEntities method"
        tdpsLocalServiceBean.persistTdpsEntities(tdpsEntityDataList)
        then: "Assert response"
        def error = thrown(ExpectedException)
        where : "Entity details"
        EntityName      |    EntityType    |     SerialNo     |        IssuerName          |  TdpsCertificateStatus     |        FilePath       |         ExpectedException
        'ENM_NBI_CA'    |   'CA_ENTITY'    |'79944672e936137e'| 'ENM_Infrastructure_CA'    |        'ACTIVE'            |'/cert/Certificate.crt'|TrustDistributionServiceException
    }
}
