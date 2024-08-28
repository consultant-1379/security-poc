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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * Node of a tree in data structure containing data, parent and child
 *
 * @author xnagcho
 * @param <T>
 */
@XmlRootElement(name = "CA-Hierarchy")
@XmlAccessorType(XmlAccessType.PROPERTY)
public class TreeNode<T> implements Serializable {

    private static final long serialVersionUID = -5094989389760293215L;

    private T data;

    private TreeNode<T> parent;

    private List<TreeNode<T>> childs = new ArrayList<TreeNode<T>>();

    /**
     * @return the data
     */
    @XmlTransient
    public T getData() {
        return data;
    }

    /**
     * @param data
     *            the data to set
     */

    public void setData(final T data) {
        this.data = data;
    }

    /**
     * @return the parent
     */
    @XmlTransient
    public TreeNode<T> getParent() {
        return parent;
    }

    /**
     * @param parent
     *            the parent to set
     */

    public void setParent(final TreeNode<T> parent) {
        this.parent = parent;
    }

    /**
     * @return the childs
     */
    @XmlElement(name = "Children")
    public List<TreeNode<T>> getChilds() {
        return childs;
    }

    /**
     * @param childs
     *            the childs to set
     */
    public void setChilds(final List<TreeNode<T>> childs) {
        this.childs = childs;
    }

    @XmlElement(name = "CAName")
    public String getCAName() {
        final CAEntity caEntity = (CAEntity) data;
        return caEntity.getCertificateAuthority().getName();
    }

    /**
     * Method for getting Siblings count
     *
     * @return
     */
    @XmlElement(name = "Siblings")
    public int getSiblings() {

        if (parent != null) {
            return parent.childs.size() - 1;
        }
        return 0;
    }

    /**
     * Method for getting parentNode Name
     *
     * @return
     */
    @XmlElement(name = "ParentCAName")
    public String getParentName() {
        CAEntity caEntity = null;
        if (parent != null) {
            caEntity = (CAEntity) parent.getData();
            return caEntity.getCertificateAuthority().getName();
        }
        return null;
    }

    /**
     * Method for getting Max depth of the tree
     *
     * @return
     */
    public int getTreeDepth() {
        final int depth = 1;
        int max = 0;
        for (final TreeNode<T> child : childs) {
            final int childDepth = child.getTreeDepth();
            if (max < childDepth) {
                max = childDepth;
            }
        }
        return depth + max;
    }

    /**
     * Method for getting maximum child
     *
     * @return
     */
    public int getMaxChilds() {
        int max = childs.size();
        for (final TreeNode<T> child : childs) {
            final int maxChilds = child.getMaxChilds();
            if (maxChilds > max) {
                max = maxChilds;
            }
        }
        return max;
    }

    /**
     * Method for getting String formatted hierarchy if it is tail node
     *
     * @return
     */
    public String print() {
        return print("", true);
    }

    /**
     * Method for getting String formatted hierarchy
     *
     * @param prefix
     * @param isTail
     * @return
     */
    public String print(final String prefix, final boolean isTail) {
        final CAEntity caEntity = (CAEntity) data;
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.append( "\n" + prefix + (isTail ? "|___ " : "|--- ") + caEntity.getCertificateAuthority().getName());
        for (int i = 0; i < childs.size() - 1; i++) {
            strBuilder.append(childs.get(i).print(prefix + (isTail ? "     " : "|     "), false));
        }
        if (childs.size() > 0) {
            strBuilder.append(childs.get(childs.size() - 1).print(prefix + (isTail ? "     " : "|     "), true));
        }
        return strBuilder.toString();
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        final CAEntity currentCA = (CAEntity) data;
        CAEntity parentData = null;
        if (parent != null) {
            parentData = (CAEntity) parent.getData();
        }
        return "TreeNode [" + (currentCA != null ? "data=" + currentCA.getCertificateAuthority().getName() + ", " : "")
                + (parentData != null ? "parent=" + parentData.getCertificateAuthority().getName() + ", " : "")
                + (parentData != null ? "Number OF Siblings : " + parent.childs.size() + ", " : "")
                + (childs != null ? "childs=" + childs : "") + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (data == null ? 0 : data.hashCode());
        result = prime * result + (parent == null ? 0 : parent.hashCode());
        result = prime * result + (childs == null ? 0 : childs.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof TreeNode)) {
            return false;
        }
        final TreeNode<T> other = (TreeNode<T>) obj;
        if (childs == null) {
            if (other.childs != null) {
                return false;
            }
        } else if (other.childs == null) {
            return false;
        } else {
            if (childs.size() != other.childs.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final TreeNode<T> child : childs) {
                for (final TreeNode<T> otherChild : other.childs) {
                    if (child.equals(otherChild)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        if (data == null) {
            if (other.data != null) {
                return false;
            }
        } else if (!data.equals(other.data)) {
            return false;
        }

        return true;
    }
}
