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
package com.ericsson.oss.itpf.security.pki.manager.model;

import static org.junit.Assert.*;

import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.TreeNodeSetUpData;

/**
 * Test class that holds the test cases for {@link TreeNode} class.
 * 
 * @author xnagcho
 * 
 */
public class TreeNodeTest {

    /**
     * Test the count of childs method.
     */
    @Test
    public void testChildCount() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(0, treeNode.getChilds().size());
    }

    /**
     * Test getData method in TreeNode
     */
    @Test
    public void testData() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(new TreeNodeSetUpData().getCAEntityForEqual(), treeNode.getData());
    }

    /**
     * Test getParentName method in TreeNode
     */
    @Test
    public void testGetParentName() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(null, treeNode.getParentName());
    }

    /**
     * Test toString method of TreeNode
     */
    @Test
    public void testToString() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        final String message = "TreeNode [data=RootCA, childs=[]]";
        assertEquals(message, treeNode.toString());
    }

    /**
     * Test getTreeDepth method in TreeNode with root CA as data
     */
    @Test
    public void testGetTreeDepthwithRootCA() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(1, treeNode.getTreeDepth());
    }

    /**
     * Test getTreeDepth method in TreeNode with sub CA as data
     */
    @Test
    public void testGetTreeDepthwithSubCA() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNodeWithSubCA();
        assertEquals(2, treeNode.getTreeDepth());
    }

    /**
     * Test print method in TreeNode with child CA
     */
    @Test
    public void testPrintwithSubCA() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNodeWithSubCA();
        final String message = "\n|--- RootCA" + "\n" + "|     |___ SubCA";
        assertEquals(message, treeNode.print("", false));
    }

    /**
     * Test getSiblings method in TreeNode
     */
    @Test
    public void testGetSiblings() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(0, treeNode.getSiblings());
    }

    /**
     * Test getMaxChilds method in TreeNode
     */
    @Test
    public void testGetMaxChilds() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals(0, treeNode.getMaxChilds());
    }

    /**
     * Test getCAName method in TreeNode
     */
    @Test
    public void testGetCAName() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals("RootCA", treeNode.getCAName());
    }

    /**
     * Test print method in TreeNode with root CA as data
     */
    @Test
    public void testPrint() {
        final TreeNode<CAEntity> treeNode = new TreeNodeSetUpData().getTreeNode();
        assertEquals("\n|--- RootCA", treeNode.print("", false));
    }

    /**
     * Test HashCode method for TreeNode
     */
    @Test
    public void testHashCode() {
        final TreeNode<CAEntity> treeNode1 = new TreeNodeSetUpData().getTreeNode();
        final TreeNode<CAEntity> treeNode2 = new TreeNodeSetUpData().getTreeNode();
        assertEquals(treeNode1.hashCode(), treeNode2.hashCode());
    }

    /**
     * Test Equals method for TreeNode
     */
    @Test
    public void testEquals() {
        final TreeNode<CAEntity> treeNode1 = new TreeNodeSetUpData().getTreeNodeWithSubCA();
        final TreeNode<CAEntity> treeNode2 = new TreeNodeSetUpData().getTreeNodeWithSubCANotEqual();
        assertEquals(treeNode1, treeNode1);
        assertNotEquals(treeNode1, treeNode2);
    }

}
