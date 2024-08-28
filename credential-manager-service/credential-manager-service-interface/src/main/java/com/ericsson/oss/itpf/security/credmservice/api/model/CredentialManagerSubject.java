/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.X509Name;

public class CredentialManagerSubject implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -4579496651604977575L;

    protected String commonName;
    protected String surName;
    protected String countryName;
    protected String localityName;
    protected String stateOrProvinceName;
    protected String streetAddress;
    protected String organizationalUnitName;
    protected String organizationName;
    protected String dnQualifier;
    protected String title;
    protected String givenName;
    protected String serialNumber;

    /**
     * Gets the value of the commonName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Sets the value of the commonName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setCommonName(final String value) {
        this.commonName = value;
    }

    /**
     * Gets the value of the surName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getSurName() {
        return surName;
    }

    /**
     * Sets the value of the surName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setSurName(final String value) {
        this.surName = value;
    }

    /**
     * Gets the value of the countryName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getCountryName() {
        return countryName;
    }

    /**
     * Sets the value of the countryName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setCountryName(final String value) {
        this.countryName = value;
    }

    /**
     * Gets the value of the localityName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getLocalityName() {
        return localityName;
    }

    /**
     * Sets the value of the localityName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setLocalityName(final String value) {
        this.localityName = value;
    }

    /**
     * Gets the value of the stateOrProvinceName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getStateOrProvinceName() {
        return stateOrProvinceName;
    }

    /**
     * Sets the value of the stateOrProvinceName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setStateOrProvinceName(final String value) {
        this.stateOrProvinceName = value;
    }

    /**
     * Gets the value of the streetAddress property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getStreetAddress() {
        return streetAddress;
    }

    /**
     * Sets the value of the streetAddress property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setStreetAddress(final String value) {
        this.streetAddress = value;
    }

    /**
     * Gets the value of the organizationalUnitName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getOrganizationalUnitName() {
        return organizationalUnitName;
    }

    /**
     * Sets the value of the organizationalUnitName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setOrganizationalUnitName(final String value) {
        this.organizationalUnitName = value;
    }

    /**
     * Gets the value of the organizationName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getOrganizationName() {
        return organizationName;
    }

    /**
     * Sets the value of the organizationName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setOrganizationName(final String value) {
        this.organizationName = value;
    }

    /**
     * Gets the value of the dnQualifier property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getDnQualifier() {
        return dnQualifier;
    }

    /**
     * Sets the value of the dnQualifier property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setDnQualifier(final String value) {
        this.dnQualifier = value;
    }

    /**
     * Gets the value of the title property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getTitle() {
        return title;
    }

    /**
     * Sets the value of the title property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setTitle(final String value) {
        this.title = value;
    }

    /**
     * Gets the value of the givenName property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getGivenName() {
        return givenName;
    }

    /**
     * Sets the value of the givenName property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setGivenName(final String value) {
        this.givenName = value;
    }

    /**
     * Gets the value of the serialNumber property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the value of the serialNumber property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setSerialNumber(final String value) {
        this.serialNumber = value;
    }

    public String retrieveSubjectDN() {
        String subjectDN = "";

        if (commonName != null) {
            subjectDN += "CN" + "=" + commonName;
        }
        if (surName != null) {
            subjectDN += "," + "SURNAME" + "=" + surName;
        }
        if (countryName != null) {
            subjectDN += "," + "C" + "=" + countryName;
        }
        if (localityName != null) {
            subjectDN += "," + "L" + "=" + localityName;
        }
        if (stateOrProvinceName != null) {
            subjectDN += "," + "ST" + "=" + stateOrProvinceName;
        }
        if (streetAddress != null) {
            subjectDN += "," + "STREET" + "=" + streetAddress;
        }
        if (organizationalUnitName != null) {
            subjectDN += "," + "OU" + "=" + organizationalUnitName;
        }
        if (organizationName != null) {
            subjectDN += "," + "O" + "=" + organizationName;
        }
        if (dnQualifier != null) {
            subjectDN += "," + "DN" + "=" + dnQualifier;
        }
        if (title != null) {
            subjectDN += "," + "T" + "=" + title;
        }
        if (givenName != null) {
            subjectDN += "," + "GIVENNAME" + "=" + givenName;
        }
        if (serialNumber != null) {
            subjectDN += "," + "SN" + "=" + serialNumber;
        }

        if (subjectDN.startsWith(",")) {
            subjectDN = subjectDN.substring(1);
        }

        return subjectDN;

    }

    @Override
    public String toString() {
        return " Subject: [ commonName: " + commonName + " surName: " + surName + " countryName: " + countryName + " localityName: " + localityName
                + " stateOrProvinceName: " + stateOrProvinceName + " streetAddress: " + streetAddress + " organizationalUnitName: "
                + organizationalUnitName + " organizationName: " + organizationName + " dnQualifier: " + dnQualifier + " title: " + title
                + " givenName: " + givenName + " serialNumber: " + serialNumber + " ] ";
    }

    public CredentialManagerSubject updateFromSubjectDN(final String distinguishName) {
        final X509Name x509Name = new X509Name(false, distinguishName);
        final Vector<String> commonNames = x509Name.getValues(X509Name.CN);
        if (!commonNames.isEmpty()) {
            commonName = commonNames.get(0);
        }
        final Vector<String> surNames = x509Name.getValues(X509Name.SURNAME);
        if (!surNames.isEmpty()) {
            surName = surNames.get(0);
        }
        final Vector<String> countryNames = x509Name.getValues(X509Name.C); //TODO: DespicableUs BouncyCastle countryCode
        if (!countryNames.isEmpty()) {
            countryName = countryNames.get(0);
        }
        final Vector<String> localityNames = x509Name.getValues(X509Name.L);
        if (!localityNames.isEmpty()) {
            localityName = localityNames.get(0);
        }
        final Vector<String> stateOrProvinceNames = x509Name.getValues(X509Name.ST);
        if (!stateOrProvinceNames.isEmpty()) {
            stateOrProvinceName = stateOrProvinceNames.get(0);
        }
        final Vector<String> streetAddresses = x509Name.getValues(X509Name.STREET); //TODO: DespicableUs BouncyCastle street
        if (!streetAddresses.isEmpty()) {
            streetAddress = streetAddresses.get(0);
        }
        final Vector<String> organizationalUnitNames = x509Name.getValues(X509Name.OU);
        if (!organizationalUnitNames.isEmpty()) {
            organizationalUnitName = organizationalUnitNames.get(0);
        }
        final Vector<String> organizationNames = x509Name.getValues(X509Name.O); //TODO: DespicableUs BouncyCastle organization
        if (!organizationNames.isEmpty()) {
            organizationName = organizationNames.get(0);
        }
        final Vector<String> dnQualifiers = x509Name.getValues(X509Name.DN_QUALIFIER);
        if (!dnQualifiers.isEmpty()) {
            dnQualifier = dnQualifiers.get(0);
        }
        final Vector<String> titles = x509Name.getValues(X509Name.T);
        if (!titles.isEmpty()) {
            title = titles.get(0);
        }
        final Vector<String> givenNames = x509Name.getValues(X509Name.GIVENNAME);
        if (!givenNames.isEmpty()) {
            givenName = givenNames.get(0);
        }
        final Vector<String> serialNumbers = x509Name.getValues(X509Name.SERIALNUMBER);
        if (!serialNumbers.isEmpty()) {
            serialNumber = serialNumbers.get(0);
        }
        return this;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((commonName == null) ? 0 : commonName.hashCode());
        result = prime * result + ((countryName == null) ? 0 : countryName.hashCode());
        result = prime * result + ((dnQualifier == null) ? 0 : dnQualifier.hashCode());
        result = prime * result + ((givenName == null) ? 0 : givenName.hashCode());
        result = prime * result + ((localityName == null) ? 0 : localityName.hashCode());
        result = prime * result + ((organizationName == null) ? 0 : organizationName.hashCode());
        result = prime * result + ((organizationalUnitName == null) ? 0 : organizationalUnitName.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((stateOrProvinceName == null) ? 0 : stateOrProvinceName.hashCode());
        result = prime * result + ((streetAddress == null) ? 0 : streetAddress.hashCode());
        result = prime * result + ((surName == null) ? 0 : surName.hashCode());
        result = prime * result + ((title == null) ? 0 : title.hashCode());
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
        final CredentialManagerSubject other = (CredentialManagerSubject) obj;
        if (commonName == null) {
            if (other.commonName != null) {
                return false;
            }
        } else if (!commonName.equals(other.commonName)) {
            return false;
        }
        if (countryName == null) {
            if (other.countryName != null) {
                return false;
            }
        } else if (!countryName.equals(other.countryName)) {
            return false;
        }
        if (dnQualifier == null) {
            if (other.dnQualifier != null) {
                return false;
            }
        } else if (!dnQualifier.equals(other.dnQualifier)) {
            return false;
        }
        if (givenName == null) {
            if (other.givenName != null) {
                return false;
            }
        } else if (!givenName.equals(other.givenName)) {
            return false;
        }
        if (localityName == null) {
            if (other.localityName != null) {
                return false;
            }
        } else if (!localityName.equals(other.localityName)) {
            return false;
        }
        if (organizationName == null) {
            if (other.organizationName != null) {
                return false;
            }
        } else if (!organizationName.equals(other.organizationName)) {
            return false;
        }
        if (organizationalUnitName == null) {
            if (other.organizationalUnitName != null) {
                return false;
            }
        } else if (!organizationalUnitName.equals(other.organizationalUnitName)) {
            return false;
        }
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (stateOrProvinceName == null) {
            if (other.stateOrProvinceName != null) {
                return false;
            }
        } else if (!stateOrProvinceName.equals(other.stateOrProvinceName)) {
            return false;
        }
        if (streetAddress == null) {
            if (other.streetAddress != null) {
                return false;
            }
        } else if (!streetAddress.equals(other.streetAddress)) {
            return false;
        }
        if (surName == null) {
            if (other.surName != null) {
                return false;
            }
        } else if (!surName.equals(other.surName)) {
            return false;
        }
        if (title == null) {
            if (other.title != null) {
                return false;
            }
        } else if (!title.equals(other.title)) {
            return false;
        }
        return true;
    }

}
