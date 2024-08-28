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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement;

import java.io.File;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreFileWriterHelper;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityCertificateOperationsHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.adapter.EntitiesFilterAdapter;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.validators.DTOValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching list of {@link Entity}, {@link CAEntity} objects and also for deleting an entity object of given ID.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
@Path("/entitylist")
public class EntityListResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private EntityManagementServiceLocal entityManagementServiceLocal;

    @Inject
    private DTOValidator dtoValidator;

    @Inject
    private EntitiesFilterAdapter entityFilterAdapter;

    @Inject
    private CommonUtil commonUtil;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    @Inject
    EntityCertificateOperationsHelper entityListResourceHelper;

    @Inject
    KeyStoreHelper keyStoreHelper;

    @Inject
    CertificateResourceHelper certificateResourceHelper;

    @Inject
    KeyStoreFileWriterHelper keyStoreFileWriterHelper;

    @Inject
    InputValidator filterValidation;

    @Inject
    CSRBuilder cSRBuilder;

    private final static String ENTITY_DELETED = "Entity deleted Successfully.";

    /**
     * This method returns the count of entities that match with {@link EntityFilterDTO}.
     * 
     * @param entityfilterDTO
     *            EntityFilterDTO object containing filter conditions based on which entities has to be filtered.
     * 
     * @return count number of entities that match with given filter criteria
     * @throws IOException
     * @throws JsonProcessingException
     */
    @POST
    @Path("/count")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response count(final EntityFilterDTO entityfilterDTO) throws JsonProcessingException {
        int count = 0;

        logger.debug("Retrieving count of entities that match with given filter criteria {}.", entityfilterDTO);

        final boolean isEntityFilterDTOValid = dtoValidator.validateEntityFilterDTO(entityfilterDTO);

        if (!isEntityFilterDTOValid) {
            return Response.status(Status.OK).entity(count).build();
        }

        final EntitiesFilter entitiesFilter = entityFilterAdapter.toEntitiesFilterForCount(entityfilterDTO);

        count = entityManagementServiceLocal.getEntitiesCountByFilter(entitiesFilter);

        logger.debug("Successfully retrieved entities count {} matching with filterDTO {}.", count, entityfilterDTO);

        return Response.status(Status.OK).entity(count).build();
    }

    /**
     * This method returns list of Entities that match with the given filter criteria, that lie between given offset, limit values and places the entity with ID set in {@link CertificateRequestDTO} in
     * the first row.
     * 
     * @param entityDTO
     *            specifies criteria, offset, limit values based on which entities have to be filtered.
     * 
     * @return a JSON Array containing the entities.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @POST
    @Path("/fetch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(final EntityDTO entityDTO) throws JsonProcessingException {
        logger.debug("Fetching entities.");

        final boolean isEntityDTOValid = dtoValidator.validateEntityDTO(entityDTO);

        if (!isEntityDTOValid) {
            final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

            final String result = mapper.writeValueAsString(new ArrayList<String>());
            return Response.status(Status.OK).entity(result).build();
        }

        final EntitiesFilter entitiesFilter = entityFilterAdapter.toEntitiesFilterForFetch(entityDTO);

        String result = null;
        final List<AbstractEntityDetails> entityDetails = entityManagementServiceLocal.getEntityDetailsByFilter(entitiesFilter);

        result = commonUtil.placeAttributeAtFirstForEntities(getEntityDetailsInJson(entityDetails), AttributeType.ID, String.valueOf(entityDTO.getId()));

        logger.debug("Successfully fetched the entities.");

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This method issues certificate/s for CA_ENTITY and ENTITY and downloads the certificate/s in the given format
     * 
     * @param certificateRequestDTO
     *            object containing all the required fields to issue certificate/s through REST
     * @return download able file with certificates in given format
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     * @throws IOException
     */
    @POST
    @Path("/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response issue(final CertificateRequestDTO certificateRequestDTO) throws CertificateServiceException, IOException {

        String resourceName = null;

        logger.info("Issuing certificates.");

        if (certificateRequestDTO.getType().equals(EntityType.CA_ENTITY)) {
            resourceName = entityListResourceHelper.issueCertificateForCA(certificateRequestDTO);
        } else if (certificateRequestDTO.getType().equals(EntityType.ENTITY)) {
            resourceName = entityListResourceHelper.issueCertificateForEntity(certificateRequestDTO);
        }

        final File file = new File(Constants.TMP_DIR + Constants.FILE_SEPARATOR + resourceName);

        final Response response = Response.ok(commonUtil.getStreamingOutput(file), MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"")
                .build();

        if (file.exists()) {
            file.delete();
        }
        logger.info("Successfully issued certificate/s and given for download in {} format.", certificateRequestDTO.getFormat());

        return response;
    }

    /**
     * This service must convert base64 encoded CSR data into DER encoded data and creates pkcs10CertificationRequest, The download starts directly after the certificate is generated successfully.
     * 
     * @param keyStoreFileDTO
     *            . Object contains enityName, CSR base64 encoded data, chain to include full CA chain or not and download format and the password for jks download.
     * @throws CertificateServiceException
     *             Thrown in case key store generation failures.
     * @throws IOException
     *             thrown in the event of corrupted data, or an incorrect structure.
     */
    @POST
    @Path("/issue/csrupload")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response issue(final KeyStoreFileDTO keyStoreFileDTO) throws CertificateServiceException, IOException {

        logger.info("Issuing certificates for Entity.");

        filterValidation.validateFileDTO(keyStoreFileDTO);

        final byte[] data = Base64.decode(keyStoreFileDTO.getData());
        final CertificateRequest certificateRequest = cSRBuilder.generateCSR(new String(data));

        final Certificate certificate = pkiManagerEServiceProxy.getEntityCertificateManagementService().generateCertificate(keyStoreFileDTO.getName(), certificateRequest);
        final List<Certificate> certificates = entityListResourceHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), certificate);

        final KeyStoreInfo keyStoreInfo = keyStoreHelper.createKeyStoreInfo(keyStoreFileDTO.getName(), keyStoreFileDTO.getFormat(), keyStoreFileDTO.getPassword(), keyStoreFileDTO.getName());
        final String resourceName = keyStoreHelper.createKeyStore(keyStoreInfo, certificates);

        final File file = new File(Constants.TMP_DIR + Constants.FILE_SEPARATOR + resourceName);
        final Response response = Response.ok(commonUtil.getStreamingOutput(file), MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"")
                .build();

        if (file.exists()) {
            file.delete();
        }
        logger.info("Successfully issued certificate/s and given for download in {} format.", keyStoreFileDTO.getFormat());

        return response;
    }

    private JSONArray getEntityDetailsInJson(final List<AbstractEntityDetails> entityDetails) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITIES_FETCH_MAPPER);

        final JSONArray entityDetailsArray = new JSONArray(mapper.writeValueAsString(entityDetails));

        return updateEntityTypeWithValue(entityDetailsArray);

    }

    private JSONArray updateEntityTypeWithValue(final JSONArray mergedArray) {

        for (int i = 0; i < mergedArray.length(); i++) {
            final JSONObject jsonObject = mergedArray.getJSONObject(i);
            final String entityType = jsonObject.getString("type");
            final EntityType entityTypeEnum = EntityType.valueOf(entityType);
            jsonObject.put("entityType", entityTypeEnum.getValue());
            mergedArray.put(i, jsonObject);
        }

        return mergedArray;
    }

    /**
     * This method deletes a entity based on the values set in path parameters {@link EntityType}, id.
     * 
     * @param entityType
     *            type of entity to be deleted.
     * @param id
     *            Id of the entity to be deleted
     * 
     * @return a message whether the entity has been deleted successfully or not.
     * @throws IOException
     * @throws JsonProcessingException
     */
    @DELETE
    @Path("/delete/{entitytype}/{id}")
    public Response delete(@PathParam("entitytype") final EntityType entityType, @PathParam("id") final int id) throws JsonProcessingException, IOException {
        logger.debug("Deleting {} with ID {}.", entityType.getValue(), id);

        if (entityType == EntityType.CA_ENTITY) {
            final CAEntity caEntity = getCAEntityForDelete(id);
            pkiManagerEServiceProxy.getEntityManagementService().deleteEntity(caEntity);
        } else if (entityType == EntityType.ENTITY) {
            final Entity entity = getEntityForDelete(id);
            pkiManagerEServiceProxy.getEntityManagementService().deleteEntity(entity);
        }

        logger.debug("Successfully deleted {} with ID {}.", entityType.getValue(), id);

        return Response.status(Status.OK).entity(ENTITY_DELETED).build();
    }

    private CAEntity getCAEntityForDelete(final int id) {
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(id);
        caEntity.setCertificateAuthority(certificateAuthority);

        return caEntity;
    }

    private Entity getEntityForDelete(final int id) {
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(id);
        entity.setEntityInfo(entityInfo);

        return entity;
    }

}
