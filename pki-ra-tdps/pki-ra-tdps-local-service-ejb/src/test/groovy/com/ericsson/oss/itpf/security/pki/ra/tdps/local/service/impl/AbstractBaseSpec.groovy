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

import java.security.cert.X509Certificate
import java.util.List
import javax.inject.Inject
import javax.persistence.EntityManager
import javax.persistence.PersistenceException
import javax.persistence.Query
import com.ericsson.cds.cdi.support.configuration.InjectionProperties
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSEntityTypeMapper
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.PersistenceManager
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo
import com.ericsson.oss.services.pm.modeling.schema.gen.kpi_formula.Add
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility


/**
 * This class is to prepare the test data for publish, unpublish and list the certificates from TDPS DB.
 *
 *  @author xvadyas
 *
 */

public class AbstractBaseSpec  extends CdiSpecification {

    @MockedImplementation
    PersistenceManager persistenceManager

    @Inject
    TDPSEntityTypeMapper tDPSEntityTypeMapper

    @Inject
    TDPSEntityData tDPSEntityData

    TestSetupInitializer testSetupInitializer
    EntityManager entityManager
    Query query

    List<TDPSEntityData> tdpsEntityDataList = new ArrayList<TDPSEntityData>()

    @Override
    public Object addAdditionalInjectionProperties(InjectionProperties injectionProperties) {
        injectionProperties.autoLocateFrom('com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.impl')
    }


    def setup() {
        testSetupInitializer = new TestSetupInitializer()
        entityManager = Stub(EntityManager.class)
        query = Stub(Query.class)
    }

    def setMocks(final TDPSCertificateInfo tdpsCertificateInfo){
        String entityName = tdpsCertificateInfo.getEntityName()
        final TDPSEntity entityType = tDPSEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType())
        String serialNo = tdpsCertificateInfo.getSerialNumber()
        String issuerName = tdpsCertificateInfo.getIssuerName()

        persistenceManager.getEntityManager() >> entityManager
        persistenceManager.getEntityManager().createNamedQuery("TDPSEntityData.findByEntityNameAndType") >> query
        query.setParameter("entityName", entityName) >> query
        query.setParameter("entityType", entityType) >> query
        query.setParameter("serialNo", serialNo) >> query
        query.setParameter("issuerName", issuerName) >> query
    }

    def setTDPSEntityData(final TDPSCertificateInfo tdpsCertificateInfo, final String filePath) {
        setMocks(tdpsCertificateInfo)
        tdpsEntityDataList = testSetupInitializer.getEntityDetails(tdpsCertificateInfo, filePath)
        if(tdpsEntityDataList.isEmpty() && tdpsCertificateInfo.getEntityName()!= null){
            query.getResultList() >> tdpsEntityDataList
        }else if(!(tdpsEntityDataList.isEmpty()) && tdpsCertificateInfo.getEntityName()!= null){
            query.getResultList() >> tdpsEntityDataList
            TDPSEntityData tdpsEntity = (TDPSEntityData) tdpsEntityDataList.get(0);
            persistenceManager.getEntityManager().merge(tdpsEntity) >> tdpsEntity
        }else if (!(tdpsEntityDataList.isEmpty()) && tdpsCertificateInfo.getEntityName() == null){
            tdpsEntityDataList = testSetupInitializer.getEntityDetails(tdpsCertificateInfo, filePath)
            query.getResultList() >> tdpsEntityDataList
            TDPSEntityData tdpsEntity = (TDPSEntityData) tdpsEntityDataList.get(0)
            persistenceManager.getEntityManager().merge(tdpsEntity) >> { throw new PersistenceException() }
        }
        else {
            query.getResultList() >> { throw new PersistenceException() }
        }
    }

    def setMocks_List(final TDPSEntityData tDPSEntityData){
        persistenceManager.getEntityManager() >> entityManager
        persistenceManager.getEntityManager().createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType") >> query
        query.setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName()) >> query
        query.setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()) >> query
        query.setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo()) >> query
        query.setParameter(Constants.CERTIFICATE_STATUS_PARAM, tDPSEntityData.getTdpsCertificateStatus()) >> query
        query.setParameter(Constants.ISSUER_NAME_PARAM, tDPSEntityData.getIssuerName()) >> query
    }

    def setTDPSEntityData_List(final String entityName, final TDPSEntity entityType, final String issuerName, final String serialNo, final TDPSCertificateStatus tdpsCertificateStatus, final String filePath){

        if(entityName!= null){
            tDPSEntityData = testSetupInitializer.getTDPSEntityData(entityName, entityType, issuerName, serialNo, tdpsCertificateStatus, filePath)
            tdpsEntityDataList.add(tDPSEntityData)
            X509Certificate certificate = CertificateUtility.getCertificateFromByteArray(tDPSEntityData.getCertificate())
            String name = StringUtility.getCNfromDN(certificate.subjectDN.name)
            if( name.equalsIgnoreCase(entityName)){
                setMocks_List(tDPSEntityData)
                query.getSingleResult() >> tDPSEntityData
            }else{
                setMocks_List(tDPSEntityData)
                query.getSingleResult() >> null
            }
        }else{
            tdpsEntityDataList.add(tDPSEntityData)
            setMocks_List(tDPSEntityData)
            query.getSingleResult() >> { throw new PersistenceException() }
        }
    }

    def setInvalidTDPSEntityData_List(final String entityName, final TDPSEntity entityType, final String issuerName, final String serialNo, final TDPSCertificateStatus tdpsCertificateStatus, final String filePath){

        tDPSEntityData = testSetupInitializer.getTDPSEntityData(entityName, entityType, issuerName, serialNo, tdpsCertificateStatus, filePath)
        tdpsEntityDataList.add(tDPSEntityData)
        setMocks_List(tDPSEntityData)
        query.getSingleResult() >> tDPSEntityData
        persistenceManager.getEntityManager().merge(tDPSEntityData) >> { throw new Exception() }
    }

}
