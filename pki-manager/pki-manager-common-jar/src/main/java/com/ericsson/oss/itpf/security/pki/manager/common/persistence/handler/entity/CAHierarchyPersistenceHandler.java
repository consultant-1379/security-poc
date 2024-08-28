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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * Class that holds the logic of formation of CA Hierarchy in Tree structure. It contains two operations:
 * <ul>
 * <li>Formation of trees for all root CAs in the system.</li>
 * <li>Formation of tree from a node(CA) based on CA name given.</li>
 * </ul>
 *
 * @author tcsnagc
 * @version 1.1.30
 */
public class CAHierarchyPersistenceHandler {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntitiesModelMapperFactoryv1 modelMapperFactoryv1;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    private static final String CA_NAME_PATH = "certificateAuthorityData.name";
    private static final String IS_ROOTCA_PATH = "certificateAuthorityData.rootCA";
    private static final String ISSUER_DATA = "issuerData";
    private static final String CERT_PROF_DATA = "certificateProfileData";
    private static final String ENTITY_PROF_DATA = "entityProfileData";

    /**
     * Get CA Hierarchy from given CA Name.
     *
     * @param entityName
     *            : name of the CA entity from which hierarchy need to be displayed.
     * @return TreeNode containing Hierarchy from given CA Entity
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws CANotFoundException
     *             thrown when no CA is present in Database with given name.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public TreeNode<CAEntity> getCAHierarchyByName(final String entityName) throws CAEntityNotInternalException, CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final CAEntityData cAEntityData = getCAByName(entityName);

        final TreeNode<CAEntity> cAHeirarchy = buildCAHierarchy(cAEntityData, null);

        return cAHeirarchy;
    }

    /**
     * This method returns CA Hierarchies for each root CA
     *
     * @return List of {@link TreeNode} object containing CA Hierarchies in tree format.
     * @throws CANotFoundException
     *             Throws when RootCA is not found or inactive in the system.
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public List<TreeNode<CAEntity>> getRootCAHierarchies() throws CAEntityNotInternalException, CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {
        final List<TreeNode<CAEntity>> cAHeirarchies = new ArrayList<TreeNode<CAEntity>>();

        final List<CAEntityData> rootCAEntityDatas = getAllRootCAs();

        for (final CAEntityData rootCA : rootCAEntityDatas) {

            if (!rootCA.isExternalCA()) {
                final TreeNode<CAEntity> cAHeirarchy = buildCAHierarchy(rootCA, null);
                cAHeirarchies.add(cAHeirarchy);
            }
        }

        return cAHeirarchies;
    }

    public List<String> getSubCANames(final String caName) throws  CANotFoundException, EntityServiceException {
        logger.debug("Retrieving sub CA names of: {}", caName);
        final CAEntityData caEntityData = caCertificatePersistenceHelper.getCAEntity(caName);
        final List<CAEntityData> childCAs = getSubCAEntities(caEntityData);

        final List<String> childCANames = new ArrayList<String>();
        for (CAEntityData childCA : childCAs) {
            childCANames.add(childCA.getCertificateAuthorityData().getName());
        }

        logger.debug("Retrieved sub CA names of: {}", caName);

        return childCANames;
    }

    private TreeNode<CAEntity> buildCAHierarchy(final CAEntityData caEntityData, final TreeNode<CAEntity> parent) throws CAEntityNotInternalException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        logger.debug("Building Hierarchy for: {}", caEntityData);

        final List<CAEntityData> childCAs = getSubCAEntities(caEntityData);

        final TreeNode<CAEntity> treeNode = buildTreeNode(caEntityData, parent);

        final List<TreeNode<CAEntity>> childNodes = new ArrayList<TreeNode<CAEntity>>();

        for (final CAEntityData childCA : childCAs) {
            childNodes.add(buildCAHierarchy(childCA, treeNode));
        }

        setChildsToNode(treeNode, childNodes);

        logger.debug("Built hierarchy: {}", treeNode);

        return treeNode;
    }

    private void setChildsToNode(final TreeNode<CAEntity> treeNode, final List<TreeNode<CAEntity>> childNodes) {
        if (!ValidationUtils.isNullOrEmpty(childNodes)) {
            treeNode.setChilds(childNodes);
        }
    }

    private TreeNode<CAEntity> buildTreeNode(final CAEntityData caEntityData, final TreeNode<CAEntity> parent) throws CAEntityNotInternalException, InvalidEntityException, InvalidEntityAttributeException {
        logger.debug("Building tree node for: {}", caEntityData);

        final TreeNode<CAEntity> treeNode = new TreeNode<CAEntity>();
        CAEntity cAEntity = null;
        cAEntity = modelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY).toApi(caEntityData, MappingDepth.LEVEL_1);
        treeNode.setData(cAEntity);
        treeNode.setParent(parent);

        logger.debug("Built tree node for: {}", caEntityData);

        return treeNode;
    }

    public List<CAEntityData> getSubCAEntities(final CAEntityData caEntityData) throws EntityServiceException {
        logger.debug("Retrieving sub CAs of: {}", caEntityData);

        final List<CAEntityData> childCAs = new ArrayList<CAEntityData>();

        for (final CertificateProfileData certificateProfileData : getChildCertificateProfilesFromIssuer(caEntityData)) {
            for (final EntityProfileData entityProfileData : getChildEntityProfiles(certificateProfileData)) {
                childCAs.addAll(getChildCAEntities(entityProfileData));
            }
        }

        logger.debug("Retrieved sub CAs: {}", childCAs);

        return childCAs;
    }

    private List<CertificateProfileData> getChildCertificateProfilesFromIssuer(final CAEntityData issuerData) throws EntityServiceException {
        logger.debug("Retrieving certificate profiles with issuer: {}", issuerData);

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ISSUER_DATA, issuerData);
        List<CertificateProfileData> certificateProfileDatas = null;

        try {
            certificateProfileDatas = persistenceManager.findEntitiesWhere(CertificateProfileData.class, input);
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while forming CA hierarchy for {}", issuerData.getCertificateAuthorityData().getName());
            throw new EntityServiceException(ProfileServiceErrorCodes.ERROR_IN_GETTING_CA_HIERARCHY, persistenceException);
        }

        if (certificateProfileDatas == null) {
            return new ArrayList<CertificateProfileData>();
        } else {
            return certificateProfileDatas;
        }
    }

    private List<EntityProfileData> getChildEntityProfiles(final CertificateProfileData certificateProfileData) throws EntityServiceException {
        logger.debug("Retrieving entity profiles using certificate profile: {}", certificateProfileData.getName());

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(CERT_PROF_DATA, certificateProfileData);
        List<EntityProfileData> entityProfileDatas = null;

        try {
            entityProfileDatas = persistenceManager.findEntitiesWhere(EntityProfileData.class, input);
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured in forming CA hierarchy: when retriving entity profiles from certificate profile: {}", certificateProfileData.getName());
            throw new EntityServiceException(ProfileServiceErrorCodes.ERROR_IN_GETTING_CA_HIERARCHY, persistenceException);
        }

        if (entityProfileDatas == null) {
            return new ArrayList<EntityProfileData>();
        } else {
            return entityProfileDatas;
        }
    }

    private List<CAEntityData> getChildCAEntities(final EntityProfileData entityProfileData) throws EntityServiceException {
        logger.debug("Retrieving CA Entities using entity profile: {}", entityProfileData.getName());

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_PROF_DATA, entityProfileData);
        List<CAEntityData> caEntityDatas = null;

        try {
            caEntityDatas = persistenceManager.findEntitiesWhere(CAEntityData.class, input);
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while forming CA hierarchies: while getting child CAs from entity profile: {}", entityProfileData.getName());
            throw new EntityServiceException(ProfileServiceErrorCodes.ERROR_IN_GETTING_CA_HIERARCHY, persistenceException);
        }

        if (caEntityDatas == null) {
            return new ArrayList<CAEntityData>();
        } else {
            return caEntityDatas;
        }
    }

    private List<CAEntityData> getAllRootCAs() throws CANotFoundException, EntityServiceException {
        logger.debug("Retrieving All root CAs");

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(IS_ROOTCA_PATH, true);
        List<CAEntityData> rootCAs = null;

        try {
            rootCAs = persistenceManager.findEntitiesWhere(CAEntityData.class, input);

            if (ValidationUtils.isNullOrEmpty(rootCAs)) {
                logger.error("No Root CAs found in the system");
                throw new CANotFoundException(ProfileServiceErrorCodes.NO_ROOT_CAS);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while forming CA hierarchies: While retriving root CAs");
            throw new EntityServiceException(ProfileServiceErrorCodes.ERROR_IN_GETTING_CA_HIERARCHY, persistenceException);
        }

        logger.debug("Retrieving root CAs: {}", rootCAs);

        return rootCAs;
    }

    private CAEntityData getCAByName(final String entityName) throws CANotFoundException, EntityServiceException {
        logger.debug("Retrieving CA Entity with name: {}", entityName);

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(CA_NAME_PATH, entityName);
        List<CAEntityData> cAEntities = null;

        try {
            cAEntities = persistenceManager.findEntitiesWhere(CAEntityData.class, input);

            if (ValidationUtils.isNullOrEmpty(cAEntities)) {
                logger.error("No CA found in the system with given name: {}", entityName);
                throw new CANotFoundException(ProfileServiceErrorCodes.NO_ENTITY_FOUND_WITH_NAME + entityName);
            }

        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while forming CA hierarchy for {}", entityName);
            throw new EntityServiceException(ProfileServiceErrorCodes.ERROR_IN_GETTING_CA_HIERARCHY, persistenceException);
        }

        logger.debug("Retrieved CA Entity: {}", cAEntities.get(0));
        return cAEntities.get(0);
    }
}
