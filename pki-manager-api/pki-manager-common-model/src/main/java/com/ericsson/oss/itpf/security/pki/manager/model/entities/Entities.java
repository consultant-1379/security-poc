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

package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * PKIEntities is root element in XML holding list of CAEntities and entities.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <pre>
 * &lt;complexType name="Entities">
 * &lt;complexContent>
 * &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 * &lt;sequence>
 * &lt;element name="Entity" type="Entity" minOccurs="0" maxOccurs="unbounded" />
 * &lt;element name="CAEntity" type="CAEntity" minOccurs="0" maxOccurs="unbounded" />
 * &lt;/sequence>
 * &lt;/restriction>
 * &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlRootElement(name = "Entities")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Entities", propOrder = { "entities", "cAEntities" })
public class Entities implements Serializable {

    /**
	 *
	 */
    private static final long serialVersionUID = 3676853469572658898L;
    @XmlElement(name = "Entity", required = false)
    protected List<Entity> entities = new ArrayList<Entity>();
    @XmlElement(name = "CAEntity", required = false)
    protected List<CAEntity> cAEntities = new ArrayList<CAEntity>();

    /**
     * @return the entities
     */
    public List<Entity> getEntities() {
        return entities;
    }

    /**
     * @param entities
     *            the entities to set
     */
    public void setEntities(final List<Entity> entities) {
        this.entities = entities;
    }

    /**
     * @return the cAEntities
     */
    public List<CAEntity> getCAEntities() {
        return cAEntities;
    }

    /**
     * @param cAEntities
     *            the cAEntities to set
     */
    public void setCAEntities(final List<CAEntity> cAEntities) {
        this.cAEntities = cAEntities;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "Entities [" + (null != entities ? "entities=" + entities + ", " : "") + (null != cAEntities ? "cAEntities=" + cAEntities : "") + "]";
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (cAEntities == null ? 0 : cAEntities.hashCode());
        result = prime * result + (entities == null ? 0 : entities.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Entities other = (Entities) obj;
        if (cAEntities == null) {
            if (other.cAEntities != null) {
                return false;
            }
        } else if (other.cAEntities == null) {
            return false;
        } else {
            if (cAEntities.size() != other.cAEntities.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CAEntity caEntity : cAEntities) {
                for (final CAEntity caEntityOther : other.cAEntities) {
                    if (caEntity.equals(caEntityOther)) {
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
        if (entities == null) {
            if (other.entities != null) {
                return false;
            }
        } else if (other.entities == null) {
            return false;
        } else {
            if (entities.size() != other.entities.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final Entity entity : entities) {
                for (final Entity entityOther : other.entities) {
                    if (entity.equals(entityOther)) {
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
        return true;
    }
}
