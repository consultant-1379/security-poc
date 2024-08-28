/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import java.io.Serializable;

public class Subject implements Serializable {

    private static final long serialVersionUID = -2185622296633385054L;

    private String commonName;
    private String surName;
    private String countryName;
    private String localityName;
    private String stateOrProvinceName;
    private String streetAddress;
    private String organizationalUnitName;
    private String organizationName;
    private String dnQualifier;
    private String title;
    private String givenName;
    private String serialNumber;

    /**
     * @return the commonName
     */
    public String getCommonName() {
        return this.commonName;
    }

    /**
     * @param commonName
     *            the commonName to set
     */
    public void setCommonName(final String commonName) {
        this.commonName = commonName;
    }

    /**
     * @return the surName
     */
    public String getSurName() {
        return this.surName;
    }

    /**
     * @param surName
     *            the surName to set
     */
    public void setSurName(final String surName) {
        this.surName = surName;
    }

    /**
     * @return the countryName
     */
    public String getCountryName() {
        return this.countryName;
    }

    /**
     * @param countryName
     *            the countryName to set
     */
    public void setCountryName(final String countryName) {
        this.countryName = countryName;
    }

    /**
     * @return the localityName
     */
    public String getLocalityName() {
        return this.localityName;
    }

    /**
     * @param localityName
     *            the localityName to set
     */
    public void setLocalityName(final String localityName) {
        this.localityName = localityName;
    }

    /**
     * @return the stateOrProvinceName
     */
    public String getStateOrProvinceName() {
        return this.stateOrProvinceName;
    }

    /**
     * @param stateOrProvinceName
     *            the stateOrProvinceName to set
     */
    public void setStateOrProvinceName(final String stateOrProvinceName) {
        this.stateOrProvinceName = stateOrProvinceName;
    }

    /**
     * @return the streetAddress
     */
    public String getStreetAddress() {
        return this.streetAddress;
    }

    /**
     * @param streetAddress
     *            the streetAddress to set
     */
    public void setStreetAddress(final String streetAddress) {
        this.streetAddress = streetAddress;
    }

    /**
     * @return the organizationalUnitName
     */
    public String getOrganizationalUnitName() {
        return this.organizationalUnitName;
    }

    /**
     * @param organizationalUnitName
     *            the organizationalUnitName to set
     */
    public void setOrganizationalUnitName(final String organizationalUnitName) {
        this.organizationalUnitName = organizationalUnitName;
    }

    /**
     * @return the organizationName
     */
    public String getOrganizationName() {
        return this.organizationName;
    }

    /**
     * @param organizationName
     *            the organizationName to set
     */
    public void setOrganizationName(final String organizationName) {
        this.organizationName = organizationName;
    }

    /**
     * @return the dnQualifier
     */
    public String getDnQualifier() {
        return this.dnQualifier;
    }

    /**
     * @param dnQualifier
     *            the dnQualifier to set
     */
    public void setDnQualifier(final String dnQualifier) {
        this.dnQualifier = dnQualifier;
    }

    /**
     * @return the title
     */
    public String getTitle() {
        return this.title;
    }

    /**
     * @param title
     *            the title to set
     */
    public void setTitle(final String title) {
        this.title = title;
    }

    /**
     * @return the givenName
     */
    public String getGivenName() {
        return this.givenName;
    }

    /**
     * @param givenName
     *            the givenName to set
     */
    public void setGivenName(final String givenName) {
        this.givenName = givenName;
    }

    /**
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return this.serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the serialversionuid
     */
    public static long getSerialversionuid() {
        return serialVersionUID;
    }

}
