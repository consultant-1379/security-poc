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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.*;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.TAFKeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.TAFDataPersistenceHandler;

/**
 * This class implements for handling the calls related to entity management
 * from TAF
 *
 * @author xlakdag
 *
 */
@Stateless
public class TAFCoreEntityManagementServiceLocalBean {

    @Inject
    private Logger logger;


    @Inject
    private TAFDataPersistenceHandler tafDataPersistanceHandler;
    
    @Inject
    TAFKeyPairPersistenceHandler tafKeyPairPersistenceHandler;
    
    private static final String QUERY_TO_FETCH_END_ENTITIES_BY_PART_OF_NAME= "select name from entity_info where name LIKE :name_part";
    
    private static final String QUERY_TO_FETCH_CA_ENTITIES_BY_PART_OF_NAME= "select name from certificate_authority where name LIKE :name_part ORDER BY id DESC";
    
    private static final String QUERY_TO_FETCH_KAPS_DATA_BY_PART_OF_NAME= "select ki.key_identifier_id from certificate_authority ca join ca_keys ck on ca.id=ck.ca_id join key_identifier ki on ck.key_id=ki.id where ca.name LIKE :name_part ORDER BY ca.id DESC";
    
    public void deleteTafEntities(final String entity_name){
    	
    	try {
    		
    		logger.info("Start of deleting core TAF entity data");
        	
        	final List<String> entityNames= tafDataPersistanceHandler.getEntityNameListByPartOfName(QUERY_TO_FETCH_END_ENTITIES_BY_PART_OF_NAME, entity_name);
        	
        	for (final String entityName : entityNames) {
    		
        		final Long entityId= tafDataPersistanceHandler.getDataEntityId("SELECT id from entity_info where name=:entity_name", 
        							getAttrMap("entity_name", entityName));
        		
        		final Long certificateId= tafDataPersistanceHandler.getDataEntityId("select certificate_id from ENTITY_CERTIFICATE where entity_id=:e_id", 
        								getAttrMap("e_id", entityId));
        		
        		final Long certReqId= tafDataPersistanceHandler.getDataEntityId("select certificate_request_id from certificate_generation_info where entity_info=:e_id", 
        							getAttrMap("e_id", entityId));
        		
        		final List<Long> certIDList= tafDataPersistanceHandler.getDataEntityIdList("select certificate_id from ENTITY_CERTIFICATE where entity_id=:e_id", 
        									getAttrMap("e_id", entityId));
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from ENTITY_CERTIFICATE where entity_id=:e_id", getAttrMap("e_id", entityId));
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_generation_info where entity_info=:e_id", getAttrMap("e_id", entityId));
        		
        		for (final Long certId : certIDList) {
    				tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", 
    							getAttrMap("cert_id", certId));
    			}
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where id=:c_id", getAttrMap("c_id", certificateId));
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_request where id=:cr_id", getAttrMap("cr_id", certReqId));
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request where entity_id=:e_id", getAttrMap("e_id", entityId));
        		
        		tafDataPersistanceHandler.deleteTAFEntity("delete from entity_info where id=:e_id", getAttrMap("e_id", entityId));
        	
    		}
        	
        	logger.info("End of deleting core TAF entity data");
			} catch (Exception e) {
			logger.error("Error occured while deleting TAF End Entities from PKI Core DB. Error={} " , e.getMessage(), e);
		}
    	}

	public List<String> getTafCAEntityNames(final String searchKey) {

		List<String> caEntityNames = new ArrayList<>();
		try {

			logger.info("Getting CA Entity names created through TAF in PKI Core DB");

			caEntityNames = tafDataPersistanceHandler
					.getEntityNameListByPartOfName(
							QUERY_TO_FETCH_CA_ENTITIES_BY_PART_OF_NAME,
							searchKey);

        } catch (final Exception e) {
            logger.error("Error occured while getting TAF CA Entities from PKI Core DB. Error={} " , e.getMessage(), e);
	    }

		return caEntityNames;
	}

	private Map<String, Object> getAttrMap(final String key, final Object value) {

		final Map<String, Object> attributes = new HashMap<>();
		attributes.put(key, value);

		return attributes;
	}

    public void deleteCAEntityDataByName(final String caEntityName) {
        try {
            logger.info("start of deleteCAEntityDataByName:: {} " , caEntityName);

            final Long caEntityId= tafDataPersistanceHandler.getDataEntityId("SELECT id from certificate_authority where name=:caentity_name", getAttrMap("caentity_name", caEntityName));

            final List<Long> certReqId= tafDataPersistanceHandler.getDataEntityIdList("select certificate_request_id from certificate_generation_info  where ca_entity_info=:e_id", getAttrMap("e_id", caEntityId));

            final List<Long> keyId= tafDataPersistanceHandler.getDataEntityIdList("select key_id from ca_keys where ca_id=:e_id", getAttrMap("e_id", caEntityId));

            final List<Long> certIdList= tafDataPersistanceHandler.getDataEntityIdList("select certificate_id from CA_CERTIFICATE where ca_id=:e_id", getAttrMap("e_id", caEntityId));

            for (final Long certId : certIdList) {
                deleteCAEntityForeignKeyMappings(certId, caEntityId);
            }

            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crlinfo where ca_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_generation_info WHERE certificate_generation_info.ca_entity_info=:e_id", getAttrMap("e_id", caEntityId));

            for (final long certReqIds : certReqId) {
                tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_generation_info where certificate_request_id=:cr_id", getAttrMap("cr_id", certReqIds));
                tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_request where id=:cr_id", getAttrMap("cr_id", certReqIds));
            }

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where issuer_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_keys where ca_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crl_generation_info where  caentity_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request where ca_entity_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_certificate where ca_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from entity_info where issuer_id=:e_id", getAttrMap("e_id", caEntityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_authority where id=:e_id", getAttrMap("e_id", caEntityId));

            for (final long keyIds : keyId ) {
                tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where key_id=:k_id", getAttrMap("k_id", keyIds));
                tafDataPersistanceHandler.deleteTAFEntity("delete from ca_keys where key_id=:k_id", getAttrMap("k_id", keyIds));
                tafDataPersistanceHandler.deleteTAFEntity("delete from key_identifier where id=:k_id", getAttrMap("k_id", keyIds));
            }

        } catch (final Exception e) {
            logger.error("Error occured while deleting TAF CA Entity[{}] from PKI Core DB. Error={} " , caEntityName , e.getMessage(), e);
        }

    }


    public void deleteCAEntityForeignKeyMappings(final long certId, final Long caEntityId) {
        tafDataPersistanceHandler.deleteTAFEntity("delete from CA_CERTIFICATE where certificate_id=:cert_id", getAttrMap("cert_id", certId));

        tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", getAttrMap("cert_id", certId));

        final List<Long> fkCrlInfoIdList = tafDataPersistanceHandler.getDataEntityIdList("select id from crlinfo where certificate_id=:cert_id", getAttrMap("cert_id", certId));
        for (final Long fkCrlInfoId : fkCrlInfoIdList) {
            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crlinfo where crlinfo_id=:info_id", getAttrMap("info_id", fkCrlInfoId));
        }
        tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:cert_id", getAttrMap("cert_id", certId));

        final List<Long> issuerCertIDList= tafDataPersistanceHandler.getDataEntityIdList("select id  from certificate where issuer_certificate_id=:cert_id", 
                getAttrMap("cert_id", certId));
        for (final Long issuerCertId : issuerCertIDList) {
                final List<Long> fkCrlinfoIdList = tafDataPersistanceHandler.getDataEntityIdList("select id from crlinfo where certificate_id=:issuer_cert_id", getAttrMap("issuer_cert_id", issuerCertId));
                for (final Long fkCrlinfoId : fkCrlinfoIdList) {
                     tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crlinfo where crlinfo_id=:crlinfo_id", getAttrMap("crlinfo_id", fkCrlinfoId));
                }
                tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:issuer_cert_id", getAttrMap("issuer_cert_id", issuerCertId));
        }

        tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_generation_info where certificate_id=:c_id", getAttrMap("c_id", certId));

        final Long crlGenInfoId= tafDataPersistanceHandler.getDataEntityId("select crl_generation_info_id from crl_generation_info_ca_certificate where certificate_id=:c_id", 
                getAttrMap("c_id", certId));
        tafDataPersistanceHandler.deleteTAFEntity("delete from crl_generation_info_ca_certificate where crl_generation_info_id=:crl_gen_info_id", 
                getAttrMap("crl_gen_info_id", crlGenInfoId));

        final List<Long> fkCertificateIdList = tafDataPersistanceHandler.getDataEntityIdList("select certificate_id from ca_certificate where ca_id=:c_id", getAttrMap("c_id", caEntityId));
        logger.debug("Deleting foreign key mappings for certficateIds List : [{}]", fkCertificateIdList);
        ListIterator<Long> certIDListIterator = fkCertificateIdList.listIterator(fkCertificateIdList.size());

        while (certIDListIterator.hasPrevious()) {
            long fkCertificateId=certIDListIterator.previous();
            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_certificate where certificate_id=:c_id", getAttrMap("c_id", fkCertificateId));
            tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", getAttrMap("cert_id", fkCertificateId));
            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_generation_info where certificate_id=:c_id", getAttrMap("c_id", fkCertificateId));
            tafDataPersistanceHandler.deleteTAFEntity("delete from crl_generation_info_ca_certificate where certificate_id=:crl_gen_info_id",getAttrMap("crl_gen_info_id", fkCertificateId));
            final List<Long> crlInfoIdList= tafDataPersistanceHandler.getDataEntityIdList("select id from crlinfo where certificate_id=:cert_id",getAttrMap("cert_id", fkCertificateId));
            for (final Long crlInfoId : crlInfoIdList ) {
                tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crlinfo where crlinfo_id=:crl_gen_info_id", getAttrMap("crl_gen_info_id", crlInfoId));
            }
            tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:c_id",getAttrMap("c_id", fkCertificateId));
        }

        while (certIDListIterator.hasPrevious()) {
            long fkCertificateId=certIDListIterator.previous();
            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where issuer_certificate_id=:c_id",getAttrMap("c_id", fkCertificateId));
            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where id=:c_id", getAttrMap("c_id", fkCertificateId));
        }
    }

    public void deleteTAFKapsData(final String caentity_name){

        final List<String> kmsData = tafDataPersistanceHandler.getEntityNameListByPartOfName(QUERY_TO_FETCH_KAPS_DATA_BY_PART_OF_NAME, caentity_name);

        try {
            tafKeyPairPersistenceHandler.deleteTAFCaKeys(kmsData);
        } catch (final KeyIdentifierNotFoundException | KeyAccessProviderServiceException exception) {
            logger.error("Error occured while deleting TAF data", exception);
	    }
    }
}
