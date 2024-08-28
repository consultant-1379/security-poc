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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import java.util.*;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service.TAFCoreEntityManagementServiceLocalBean;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.CAEntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.EntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.taf.TAFDataPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.TAFEntityManagementServiceLocal;

/**
 * This class implements {@link TAFEntityManagementServiceLocal} for handling the calls related to entity management from TAF
 * 
 * @author xlakdag
 * 
 */
@Stateless
public class TAFEntityManagementServiceLocalBean implements TAFEntityManagementServiceLocal {

    @Inject
    private Logger logger;

    @Inject
    private TAFDataPersistenceHandler tafDataPersistanceHandler;

    @Inject
    private TAFCoreEntityManagementServiceLocalBean coreTafPersistanceHandler;

    @Inject
    private EntityAuthorizationHandler entityAuthorizationHandler;

    @Inject
    private CAEntityAuthorizationHandler caEntityAuthorizationHandler;

    private static final String QUERY_TO_FETCH_END_ENTITIES_BY_PART_OF_NAME = "select name from entity where name LIKE :name_part";

    private static final String QUERY_TO_FETCH_CA_ENTITIES_BY_PART_OF_NAME = "select name from caentity where name LIKE :name_part ORDER BY id DESC";

    private static final String DUSGEN2_PROFILE_NAME = "DUSGen2_OAM_ECDSA_EP";

    @Override
    public List<String> getEndEntityNamesFrmPKIManager(final String entity_name) {

        List<String> entityNames = new ArrayList<String>();
        try {

            logger.info("Getting Entity names created through TAF");

            if(!(("TAF_PKI").equals(entity_name))) {
                logger.error(ErrorMessages.INVALID_NAME_FORMAT + "{} ", entity_name);
                throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NAME_FORMAT + " " + entity_name);
            }

            entityNames = tafDataPersistanceHandler.getEntityNameListByPartOfName(QUERY_TO_FETCH_END_ENTITIES_BY_PART_OF_NAME, entity_name);

        } catch (Exception e) {
            logger.error("Error Occured while getting Entity Names", e.getMessage(), e);
        }

        logger.info("Entity names retrived :: EntityNames ::: {}" , entityNames);

        return entityNames;
    }

    @Override
    public void deleteEndEntityDataFrmPKIManager(final String entityName) {

        try {

            entityAuthorizationHandler.authorizeDeleteTAFEntity();

            logger.info("Start of deleteEntityDataByName :: entityName {}" , entityName);

            final Long entityId = tafDataPersistanceHandler.getDataEntityId("select id from entity where name=:entity_name", getAttrMap("entity_name", entityName));

            final Long DUSGen2_Entity_Profile_Id = tafDataPersistanceHandler.getDataEntityId("select id from entityprofile where name=:profile_name", getAttrMap("profile_name", DUSGEN2_PROFILE_NAME));

            final Long entityProfileId = tafDataPersistanceHandler.getDataEntityId("select entity_profile_id from entity where id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            final Long certificateProfileId = tafDataPersistanceHandler.getDataEntityId("select certificate_profile_id from entityprofile where id=:entityProfileId",
                    getAttrMap("entityProfileId", entityProfileId));

            final List<Long> certificateIdList = tafDataPersistanceHandler.getDataEntityIdList("select certificate_id FROM certificate_generation_info WHERE entity_info=:endEntity_id",
                    getAttrMap("endEntity_id", entityId));

            final Long certRequestId = tafDataPersistanceHandler.getDataEntityId("select certificate_request_id FROM certificate_generation_info WHERE entity_info=:endEntity_id",
                    getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ENTITY_CERTIFICATE where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_generation_info WHERE certificate_generation_info.entity_info=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_request WHERE  id=:e_cert_req_id", getAttrMap("e_cert_req_id", certRequestId));

            for (final Long certId : certificateIdList) {
                tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", getAttrMap("cert_id", certId));
            }

            tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            if (certificateIdList.size() > 0) {
                tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate WHERE  id=:c_id", getAttrMap("c_id", certificateIdList.get(0)));
            }
            tafDataPersistanceHandler.deleteTAFEntity("delete from entity_cert_exp_notification_details where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from entity where id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            if(!(entityProfileId.equals(DUSGen2_Entity_Profile_Id))){
            tafDataPersistanceHandler.deleteTAFEntity("delete from entityprofile where id=:ep_id", getAttrMap("ep_id", entityProfileId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile_keygenerationalgorithm where certificate_profile_id=:cp_id", getAttrMap("cp_id", certificateProfileId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile where id=:cp_id", getAttrMap("cp_id", certificateProfileId));
            }

            logger.info("End of deleting Taf Entity data");

        } catch (Exception e) {
            logger.error("Error occured while deleting TAF End Entities from PKI Manager DB" + e.getMessage(), e);
        }

    }

    @Override
    public List<String> getCAEntityNamesFrmPKIManager(final String caentity_name) {

        List<String> caEntityNames = new ArrayList<String>();
        try {

            logger.info("Getting CA Entity names created through TAF");

            if(!(("TAF_PKI").equals(caentity_name))) {
                logger.error(ErrorMessages.INVALID_NAME_FORMAT + "{} ", caentity_name);
                throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NAME_FORMAT + " " + caentity_name);
            }

            caEntityNames = tafDataPersistanceHandler.getEntityNameListByPartOfName(QUERY_TO_FETCH_CA_ENTITIES_BY_PART_OF_NAME, caentity_name);

        } catch (Exception e) {
            logger.error("Error Occured while getting CA Entity Names", e.getMessage(), e);
        }

        logger.info("CA Entity names retrived :: caEntityNames ::: {}" , caEntityNames);

        return caEntityNames;
    }

    private Map<String, Object> getAttrMap(final String key, final Object value) {

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put(key, value);

        return attributes;
    }

    @Override
    public void deleteCAEntityDataFrmPKIManager(final String caEntityName) {

        caEntityAuthorizationHandler.authorizeDeleteTAFEntity();

        logger.info("Start of deleteCAEntityDataByName :: caEntityName {}" , caEntityName);

        final Long caEntID = tafDataPersistanceHandler.getDataEntityId("select id from caentity where name=:caentity_name", getAttrMap("caentity_name", caEntityName));

        final Long entityProfileId = tafDataPersistanceHandler.getDataEntityId("select entity_profile_id from caentity where id=:ca_entId", getAttrMap("ca_entId", caEntID));

        final Long certProfileId = tafDataPersistanceHandler.getDataEntityId("select certificate_profile_id from entityprofile where id=:ep_id", getAttrMap("ep_id", entityProfileId));

        final Long certificateID = tafDataPersistanceHandler.getDataEntityId("select certificate_id from CA_CERTIFICATE where ca_id= :ca_entId", getAttrMap("ca_entId", caEntID));

        final Long caCertRequestId = tafDataPersistanceHandler.getDataEntityId("select certificate_request_id from certificate_generation_info  where ca_entity_info=:ca_entId",
                getAttrMap("ca_entId", caEntID));

        final List<Long> certIDList = tafDataPersistanceHandler.getDataEntityIdList("select certificate_id from CA_CERTIFICATE where ca_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete FROM ca_certificate WHERE ca_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_generation_info WHERE certificate_generation_info.ca_entity_info=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_request WHERE  certificate_request.id=:ca_cert_req_id", getAttrMap("ca_cert_req_id", caCertRequestId));

        tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crlinfo where ca_id=:ca_entId", getAttrMap("ca_entId", caEntID));
        for (final Long certID : certIDList) {

            final List<Long> fkCertIdList = tafDataPersistanceHandler.getDataEntityIdList("select id from certificate where issuer_certificate_id=:cert_id", getAttrMap("cert_id", certificateID));

            for (final Long fkCertId : fkCertIdList) {
                tafDataPersistanceHandler.deleteTAFEntity("delete FROM crl_generation_info_ca_certificate WHERE  certificate_id=:cert_id", getAttrMap("cert_id", fkCertId));
            }
            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate WHERE  issuer_certificate_id=:c_id", getAttrMap("c_id", certificateID));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ca_certificate where certificate_id=:c_id", getAttrMap("c_id", certificateID));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificate_generation_info where certificate_id=:c_id", getAttrMap("c_id", certificateID));

            tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", getAttrMap("cert_id", certID));

            tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:cert_id", getAttrMap("cert_id", certID));

            final List<Long> issuerCertIdList = tafDataPersistanceHandler.getDataEntityIdList("select id  from certificate where issuer_certificate_id=:cert_id", getAttrMap("cert_id", certID));
            for (final Long issuercertId : issuerCertIdList) {

                tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:issuer_cert_id", getAttrMap("issuer_cert_id", issuercertId));
            }
            final Long crlGenInfoId = tafDataPersistanceHandler.getDataEntityId("select  crl_generation_info_id from crl_generation_info_ca_certificate where  certificate_id=:c_id",
                    getAttrMap("c_id", certID));

            tafDataPersistanceHandler.deleteTAFEntity("delete from crl_generation_info_ca_certificate where crl_generation_info_id=:crl_gen_info_id", getAttrMap("crl_gen_info_id", crlGenInfoId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from crlinfo where certificate_id=:c_id", getAttrMap("c_id", certificateID));
        }
        tafDataPersistanceHandler.deleteTAFEntity("delete from certificate where issuer_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete from trustcachain where caentity_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete from ca_crl_generation_info where  caentity_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request where ca_entity_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete from ca_cert_exp_notification_details where ca_id=:ca_entId", getAttrMap("ca_entId", caEntID));

        final Long dependentCertProfileId = tafDataPersistanceHandler.getDataEntityId("select id from certificateprofile where issuer_id = :ca_entId", getAttrMap("ca_entId", caEntID));
        if (dependentCertProfileId > 0) {
            tafDataPersistanceHandler.deleteTAFEntity("delete from entityprofile where certificate_profile_id=:profile_id", getAttrMap("profile_id", dependentCertProfileId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile_keygenerationalgorithm where certificate_profile_id=:profile_id",
                    getAttrMap("profile_id", dependentCertProfileId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile where id=:profile_id", getAttrMap("profile_id", dependentCertProfileId));
        }
        tafDataPersistanceHandler.deleteTAFEntity("delete from caentity where id=:ca_entId", getAttrMap("ca_entId", caEntID));

        tafDataPersistanceHandler.deleteTAFEntity("delete from caentity where entity_profile_id=:ep_id", getAttrMap("ep_id", entityProfileId));

        tafDataPersistanceHandler.deleteTAFEntity("delete from entityprofile where id=:ep_id", getAttrMap("ep_id", entityProfileId));

        tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile_keygenerationalgorithm where certificate_profile_id=:cp_id", getAttrMap("cp_id", certProfileId));

        tafDataPersistanceHandler.deleteTAFEntity("delete from certificateprofile where id=:cp_id", getAttrMap("cp_id", certProfileId));

        logger.info("End of deleteCAEntityDataByName :: caEntityName {}" , caEntityName);
    }

    @Override
    public List<List<String>> getPartitionedLists(final List<String> caEntityNames) {

        final int partitionSize = 10;
        final List<List<String>> partitions = new LinkedList<List<String>>();
        for (int i = 0; i < caEntityNames.size(); i += partitionSize) {
            partitions.add(caEntityNames.subList(i, i + Math.min(partitionSize, caEntityNames.size() - i)));
        }

        return partitions;
    }

    @Override
    public void deleteEndEntitiesFrmPKICore(final String entity_name) {

        try {
            if(!(("TAF_PKI").equals(entity_name))) {
                logger.error(ErrorMessages.INVALID_NAME_FORMAT + "{} ", entity_name);
                throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NAME_FORMAT + " " + entity_name);
            }

            entityAuthorizationHandler.authorizeDeleteTAFEntity();

            coreTafPersistanceHandler.deleteTafEntities(entity_name);

        } catch (Exception e) {
            logger.error("Error occured while deleting TAF Core Entity Data", e.getMessage(), e);
        }

    }
    
    @Override
    public void deleteCaKeysFrmKaps(final String caentity_name) {

        try {
            if(!(("TAF_PKI").equals(caentity_name))) {
                logger.error(ErrorMessages.INVALID_NAME_FORMAT + "{} ", caentity_name);
                throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NAME_FORMAT + " " + caentity_name);
            }
            caEntityAuthorizationHandler.authorizeDeleteTAFEntity();

            coreTafPersistanceHandler.deleteTAFKapsData(caentity_name);

        } catch (Exception e) {
            logger.error("Error occured while deleting TAF CA keys data", e.getMessage(), e);
        }

    }

    @Override
    public List<String> getCAEntityNamesFromPKICore(final String caentity_name) {

        if(!(("TAF_PKI").equals(caentity_name))) {
            logger.error(ErrorMessages.INVALID_NAME_FORMAT + "{} ", caentity_name);
            throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NAME_FORMAT + " " + caentity_name);
        }

        return coreTafPersistanceHandler.getTafCAEntityNames(caentity_name);

    }

    @Override
    public void deleteCAEntityDataFromPKICore(final String caEntityName) {

        try {

            caEntityAuthorizationHandler.authorizeDeleteTAFEntity();
            
            coreTafPersistanceHandler.deleteCAEntityDataByName(caEntityName);

        } catch (Exception e) {
            logger.error("Error occured while deleting TAF Core Entity Data", e.getMessage(), e);
        }

    }

    @Override
    public void deleteExtCAEndEntityDataFrmPKIManager(final String entityName) {

        try {

            entityAuthorizationHandler.authorizeDeleteTAFEntity();

            logger.info("Start of deleteExtCAEntityDataByName  :: entityName {}" , entityName);

            final Long entityId = tafDataPersistanceHandler.getDataEntityId("select id from entity where name=:entity_name", getAttrMap("entity_name", entityName));

            final List<Long> certificateIdList = tafDataPersistanceHandler.getDataEntityIdList("select certificate_id FROM certificate_generation_info WHERE entity_info=:endEntity_id",
                    getAttrMap("endEntity_id", entityId));

            final Long certRequestId = tafDataPersistanceHandler.getDataEntityId("select certificate_request_id FROM certificate_generation_info WHERE entity_info=:endEntity_id",
                    getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from ENTITY_CERTIFICATE where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_generation_info WHERE certificate_generation_info.entity_info=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate_request WHERE  id=:e_cert_req_id", getAttrMap("e_cert_req_id", certRequestId));

            for (final Long certId : certificateIdList) {
                tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request_certificate where certificate_id=:cert_id", getAttrMap("cert_id", certId));
            }

            tafDataPersistanceHandler.deleteTAFEntity("delete from revocation_request where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            if (!certificateIdList.isEmpty()) {
                tafDataPersistanceHandler.deleteTAFEntity("delete FROM certificate WHERE  id=:c_id", getAttrMap("c_id", certificateIdList.get(0)));
            }
            tafDataPersistanceHandler.deleteTAFEntity("delete from entity_cert_exp_notification_details where entity_id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            tafDataPersistanceHandler.deleteTAFEntity("delete from entity where id=:endEntity_id", getAttrMap("endEntity_id", entityId));

            logger.info("End of deleting Taf ExtCA Entity data");

        } catch (Exception e) {
            logger.error("Error occured while deleting TAF ExtCA End Entities from PKI Manager DB" + e.getMessage(), e);
        }

    }
}
