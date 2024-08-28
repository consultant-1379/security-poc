/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.domain;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


public class ConfigurationParameter {

    private String id;
    private String name;
    private String jvmIdentifier;
    private String serviceIdentifier;
    private String typeAsString;
    private String value;
    private String description;
    private Set<String> overridableInScopes;
    private List<String> values;
    private String namespace;
    private String status;
    private long lastModificationTime;
    private String type;
    private String scope;
    private Object firstNonNullValue;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getJvmIdentifier() {
        return jvmIdentifier;
    }

    public void setJvmIdentifier(String jvmIdentifier) {
        this.jvmIdentifier = jvmIdentifier;
    }

    public String getServiceIdentifier() {
        return serviceIdentifier;
    }

    public void setServiceIdentifier(String serviceIdentifier) {
        this.serviceIdentifier = serviceIdentifier;
    }

    public String getTypeAsString() {
        return typeAsString;
    }

    public void setTypeAsString(String typeAsString) {
        this.typeAsString = typeAsString;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<String> getOverridableInScopes() {
        return Optional.ofNullable(overridableInScopes).map(items -> items.stream().collect(Collectors.toSet()))
                .orElse(null);
    }

    public void setOverridableInScopes(Set<String> overridableInScopes) {
        this.overridableInScopes = Optional.ofNullable(overridableInScopes).map(items -> items.stream()
                .collect(Collectors.toSet())).orElse(null);
    }

    public List<String> getValues() {
        return Optional.ofNullable(values).map(items -> items.stream().collect(Collectors.toList())).orElse(null);
    }

    public void setValues(List<String> values) {
        this.values = Optional.ofNullable(values).map(items -> items.stream().collect(Collectors.toList())).orElse(null);
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public long getLastModificationTime() {
        return lastModificationTime;
    }

    public void setLastModificationTime(long lastModificationTime) {
        this.lastModificationTime = lastModificationTime;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Object getFirstNonNullValue() {
        return firstNonNullValue;
    }

    public void setFirstNonNullValue(Object firstNonNullValue) {
        this.firstNonNullValue = firstNonNullValue;
    }

}
