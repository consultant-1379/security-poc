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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.Date;
import javax.persistence.*;

/**
 * Represents Algorithm jpa entity. Algorithms are configured at the time installation and this entity can be used to perform CRUD operations on algorithms.
 * 
 * @author xprabil
 * 
 */
@Entity
@Table(name = "Algorithm", uniqueConstraints = @UniqueConstraint(columnNames = { "name", "key_size" }))
public class AlgorithmData implements Serializable {

    private static final long serialVersionUID = 1819146288430236567L;

    @Id
    @Column(name = "id")
    @SequenceGenerator(name = "SEQ_ALGORITHM_ID_GENERATOR", sequenceName = "SEQ_ALGORITHM_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_ALGORITHM_ID_GENERATOR")
    private long id;

    @Column(name = "type_id", nullable = false)
    private Integer type;

    @Column(unique = false)
    private String name;

    private String oid;

    @Column(name = "is_supported")
    private boolean supported;

    @Column(name = "key_size", nullable = true)
    private Integer keySize;

    @ElementCollection(targetClass = Integer.class)
    @CollectionTable(name = "algorithm_algorithmcategory", joinColumns = @JoinColumn(name = "algorithm_id"))
    @Column(name = "category_id", nullable = false)
    final private Set<Integer> categories = new HashSet<Integer>();
    
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;
    
    /**
     * Sets current timestamp  to createdDate and modifiedDate before persist of Algorithm in DB
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate the createdDate to set
     */
    public void setCreatedDate(final Date createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * @return the modifiedDate
     */
    public Date getModifiedDate() {
        return modifiedDate;
    }

    /**
     * @param modifiedDate the modifiedDate to set
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    /**
     * Sets current timestamp to modifiedDate before update of Algorithm in DB
     */
    @PreUpdate
    protected void onUpdate() {
        modifiedDate = new Date();
    }

    /**
     * Returns true if algorithm is supported else false.
     * 
     * @return the supported
     */
    public boolean isSupported() {
        return supported;
    }

    /**
     * Set true if algorithm is supported else false.
     * 
     * @param supported
     *            the supported to set
     */
    public void setSupported(final boolean supported) {
        this.supported = supported;
    }

    /**
     * Returns algorithm name.
     * 
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the algorithm name.
     * 
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * Returns algorithm id.
     * 
     * @return the algorithm id
     */
    public long getId() {
        return id;
    }

    /**
     * Sets algorithm id.
     * 
     * @param algorithm
     *            the algorithm id to set.
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * Returns the algorithm oid.
     * 
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * Sets the algorithm oid.
     * 
     * @param oid
     *            the oid to set
     */
    public void setOid(final String oid) {
        this.oid = oid;
    }

    /**
     * Returns the algorithm type.
     * 
     * @return the type
     */
    public Integer getType() {
        return type;
    }

    /**
     * Sets the algorithm type.
     * 
     * @param type
     *            the type to set
     */
    public void setType(final Integer algorithmType) {
        this.type = algorithmType;
    }

    /**
     * Returns the key size.
     * 
     * @return the keySize
     */
    public Integer getKeySize() {
        return keySize;
    }

    /**
     * Set KeySize value.
     * 
     * @param keySize
     *            the keySize to set
     */
    public void setKeySize(final Integer keySize) {
        this.keySize = keySize;
    }

    /**
     * @return the categories
     */
    public Set<Integer> getCategories() {
        final Set<Integer> algorithmCategories = new HashSet<Integer>();
        algorithmCategories.addAll(categories);
        return algorithmCategories;
    }

    /**
     * @param categories
     *            the categories to set
     */
    public void setCategories(final Set<Integer> algorithmCategories) {
        if (algorithmCategories != null) {
            this.categories.addAll(algorithmCategories);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((keySize == null) ? 0 : keySize.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        result = prime * result + (supported ? 1231 : 1237);
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + (categories.hashCode());
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
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AlgorithmData other = (AlgorithmData) obj;
        if (id != other.id) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (oid == null) {
            if (other.oid != null) {
                return false;
            }
        } else if (!oid.equals(other.oid)) {
            return false;
        }
        if (supported != other.supported) {
            return false;
        }
        if (type != other.type) {
            return false;
        }

        if (keySize == null) {
            if (other.keySize != null) {
                return false;
            }
        } else if (!keySize.equals(other.keySize)) {
            return false;
        }

        if (other.categories == null) {
                return false;
            }
        else if (categories.size() != other.categories.size()) {
            return false;
        } else {
            boolean isMatched = false;
            for (final Integer category : categories) {
                for (final Integer categoryOther : other.categories) {
                    if (category.equals(categoryOther)) {
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

    @Override
    public String toString() {
        return "AlgorithmData [id=" + id + ", type=" + type + ", name=" + name + ", oid=" + oid + ", supported=" + supported + ("categories=" + categories) + "]";
    }
}
