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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class contains the methods required for setting up data for {@link TreeNode} instances.
 * 
 * @author xnagcho
 * 
 */
public class TreeNodeSetUpData {

    private static final String EQUAL_ENTITY_PROFILE_NAME1 = "EP1";
    private static final String EQUAL_ENTITY_PROFILE_NAME2 = "EP2";

    /**
     * Method that returns valid CAEntity
     * 
     * @return CAEntity
     */
    public CAEntity getCAEntityForEqual() {

        final CertificateAuthoritySetUpData certificateAuthoritySetUpData = new CertificateAuthoritySetUpData();
        certificateAuthoritySetUpData.name("RootCA");
        final CertificateAuthority certificateAuthority = certificateAuthoritySetUpData.build();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(EQUAL_ENTITY_PROFILE_NAME1);

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(entityProfile);
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        caEntity.setType(EntityType.CA_ENTITY);

        return caEntity;
    }

    /**
     * Method that returns valid SubCAEntity
     * 
     * @return CAEntity
     */
    public CAEntity getSubCAEntityForEqual() {

        final CertificateAuthoritySetUpData certificateAuthoritySetUpData = new CertificateAuthoritySetUpData();
        certificateAuthoritySetUpData.name("SubCA");
        certificateAuthoritySetUpData.isRootCA(false);

        final CertificateAuthority certificateAuthority = certificateAuthoritySetUpData.build();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(EQUAL_ENTITY_PROFILE_NAME2);

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(entityProfile);
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        caEntity.setType(EntityType.CA_ENTITY);

        return caEntity;
    }

    /**
     * Method that returns valid CAEntity
     * 
     * @return CAEntity
     */
    public CAEntity getCAEntityForNotEqual() {

        final CertificateAuthoritySetUpData certificateAuthoritySetUpData = new CertificateAuthoritySetUpData();
        certificateAuthoritySetUpData.name("RootCANotEqual");
        final CertificateAuthority certificateAuthority = certificateAuthoritySetUpData.build();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(EQUAL_ENTITY_PROFILE_NAME1);

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(entityProfile);
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        caEntity.setType(EntityType.CA_ENTITY);

        return caEntity;
    }

    /**
     * Method that returns valid SubCAEntity
     * 
     * @return CAEntity
     */
    public CAEntity getSubCAEntityForNotEqual() {

        final CertificateAuthoritySetUpData certificateAuthoritySetUpData = new CertificateAuthoritySetUpData();
        certificateAuthoritySetUpData.name("SubCAnotEqual");
        certificateAuthoritySetUpData.isRootCA(false);

        final CertificateAuthority certificateAuthority = certificateAuthoritySetUpData.build();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(EQUAL_ENTITY_PROFILE_NAME2);

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(entityProfile);
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        caEntity.setType(EntityType.CA_ENTITY);

        return caEntity;
    }

    public TreeNode<CAEntity> getTreeNode() {
        final TreeNode<CAEntity> treeNode = new TreeNode<CAEntity>();
        treeNode.setParent(null);
        treeNode.setData(getCAEntityForEqual());
        return treeNode;
    }

    public TreeNode<CAEntity> getTreeNodeWithSubCA() {
        final TreeNode<CAEntity> treeNodeParent = new TreeNode<CAEntity>();
        treeNodeParent.setParent(null);
        treeNodeParent.setData(getCAEntityForEqual());

        final TreeNode<CAEntity> treeNodeChild = new TreeNode<CAEntity>();
        treeNodeChild.setParent(treeNodeParent);
        treeNodeChild.setData(getSubCAEntityForEqual());

        final List<TreeNode<CAEntity>> childs = new ArrayList<TreeNode<CAEntity>>();
        childs.add(treeNodeChild);
        treeNodeParent.setChilds(childs);
        return treeNodeParent;
    }

    public TreeNode<CAEntity> getTreeNodeWithSubCANotEqual() {
        final TreeNode<CAEntity> treeNodeParent = new TreeNode<CAEntity>();
        treeNodeParent.setParent(null);
        treeNodeParent.setData(getCAEntityForNotEqual());

        final TreeNode<CAEntity> treeNodeChild = new TreeNode<CAEntity>();
        treeNodeChild.setParent(treeNodeParent);
        treeNodeChild.setData(getSubCAEntityForNotEqual());

        final List<TreeNode<CAEntity>> childs = new ArrayList<TreeNode<CAEntity>>();
        childs.add(treeNodeChild);
        treeNodeParent.setChilds(childs);
        return treeNodeParent;
    }

}
