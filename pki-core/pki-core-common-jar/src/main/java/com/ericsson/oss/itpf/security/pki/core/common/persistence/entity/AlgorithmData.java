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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.entity;

import java.io.Serializable;
import java.util.*;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;

@Entity
@Table(name = "algorithm", uniqueConstraints = @UniqueConstraint(columnNames = { "name", "key_size" }))
public class AlgorithmData implements Serializable {

    private static final long serialVersionUID = 1819146288430236567L;

    @Id
    @SequenceGenerator(name = "SEQ_ALGORITHM_ID_GENERATOR", sequenceName = "SEQ_ALGORITHM_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_ALGORITHM_ID_GENERATOR")
    private long id;

    @Column(name = "type_id", nullable = false)
    private Integer type;

    private String name;

    private String oid;

    @Column(name = "is_supported")
    private boolean supported;

    @Column(name = "key_size")
    private Integer keySize;

    @ElementCollection(targetClass = Integer.class)
    @CollectionTable(name = "algorithm_algorithmcategory", joinColumns = @JoinColumn(name = "algorithm_id"))
    @Column(name = "category_id", nullable = false)
    private Set<Integer> categories = new HashSet<>();

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

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
     * @return the Algorithm type
     */
    public AlgorithmType getType() {
        return AlgorithmType.getType(this.type);
    }

    /**
     * @param algorithmType
     *            algorithm type to be set.
     */
    public void setType(final AlgorithmType algorithmType) {

        if (algorithmType == null) {
            this.type = null;
        } else {
            this.type = algorithmType.getId();
        }
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
    public Set<AlgorithmCategory> getCategories() {
        final Set<AlgorithmCategory> algorithmCategories = new HashSet<>();
        if (categories != null) {
            for (final Integer algorithmcategoryId : categories) {
                algorithmCategories.add(AlgorithmCategory.getCategory(algorithmcategoryId));
            }
        }
        return algorithmCategories;
    }

    /**
     * @param categories
     *            the categories to set
     */
    public void setCategories(final Set<AlgorithmCategory> categories) {
        if (categories != null) {
            for (final AlgorithmCategory algorithmCategory : categories) {
                this.categories.add(algorithmCategory.getId());
            }
        }
    }

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate
     *            the createdDate to set
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
     * @param modifiedDate
     *            the modifiedDate to set
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    /**
     * Sets current timestamp to createdDate and modifiedDate before persist of Algorithm in DB
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * Sets current timestamp to modifiedDate before update of Algorithm in DB
     */
    @PreUpdate
    protected void onUpdate() {
        modifiedDate = new Date();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        result = prime * result + (supported ? 1231 : 1237);
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((keySize == null) ? 0 : keySize.hashCode());
        result = prime * result + ((categories == null) ? 0 : categories.hashCode());
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
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }
        if (categories == null) {
            if (other.categories != null) {
                return false;
            }
        } else {
            if (other.categories == null) {
                return false;
            } else {
                if (categories.size() != other.categories.size()) {
                    return false;
                }
                boolean isMatched = false;
                for (final Integer categoryId : categories) {
                    for (final Integer categoryIdOther : other.categories) {
                        if (categoryId.equals(categoryIdOther)) {
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
        }
        return true;
    }

    @Override
    public String toString() {
        return "AlgorithmData [id=" + id + ", type=" + type + ", name=" + name + ", oid=" + oid + ", supported=" + supported + (null != categories ? "certificateDatas=" + categories : "") + "]";
    }
}
