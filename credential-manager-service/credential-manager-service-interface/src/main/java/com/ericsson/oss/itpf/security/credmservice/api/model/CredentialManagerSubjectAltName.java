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
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "subjectAltName", propOrder = {
    "otherName",
    "rfc822Name",
    "dNSName",
    "x400Address",
    "directoryName",
    "ediPartyName",
    "uniformResourceIdentifier",
    "iPAddress",
    "registeredID"
})
public class CredentialManagerSubjectAltName implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3473639583087609860L;
	@XmlElement(nillable = true)
    protected List<CredentialManagerOtherName> otherName;
    @XmlElement(nillable = true)
    protected List<String> rfc822Name;
    @XmlElement(name = "dNSName", nillable = true)
    protected List<String> dNSName;
    @XmlElement(nillable = true)
    protected List<String> x400Address;
    @XmlElement(nillable = true)
    protected List<String> directoryName;
    @XmlElement(nillable = true)
    protected List<CredentialManagerEdiPartyName> ediPartyName;
    @XmlElement(nillable = true)
    protected List<String> uniformResourceIdentifier;
    @XmlElement(name = "iPAddress", nillable = true)
    protected List<String> iPAddress;
    @XmlElement(nillable = true)
    protected List<String> registeredID;
    
    
    public List<CredentialManagerOtherName> getOtherName() {
        if (otherName == null) {
            otherName = new ArrayList<CredentialManagerOtherName>();
        }
        return this.otherName;
    }

    /**
     * Gets the value of the rfc822Name property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the rfc822Name property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRfc822Name().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getRfc822Name() {
        if (rfc822Name == null) {
            rfc822Name = new ArrayList<String>();
        }
        return this.rfc822Name;
    }

    /**
     * Gets the value of the dnsName property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the dnsName property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDNSName().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getDNSName() {
        if (dNSName == null) {
            dNSName = new ArrayList<String>();
        }
        return this.dNSName;
    }

    /**
     * Gets the value of the x400Address property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the x400Address property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getX400Address().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getX400Address() {
        if (x400Address == null) {
            x400Address = new ArrayList<String>();
        }
        return this.x400Address;
    }

    /**
     * Gets the value of the directoryName property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the directoryName property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDirectoryName().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getDirectoryName() {
        if (directoryName == null) {
            directoryName = new ArrayList<String>();
        }
        return this.directoryName;
    }

    /**
     * Gets the value of the ediPartyName property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the ediPartyName property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getEdiPartyName().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link CredentialManagerEdiPartyName }
     * 
     * 
     */
    public List<CredentialManagerEdiPartyName> getEdiPartyName() {
        if (ediPartyName == null) {
            ediPartyName = new ArrayList<CredentialManagerEdiPartyName>();
        }
        return this.ediPartyName;
    }

    /**
     * Gets the value of the uniformResourceIdentifier property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the uniformResourceIdentifier property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getUniformResourceIdentifier().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getUniformResourceIdentifier() {
        if (uniformResourceIdentifier == null) {
            uniformResourceIdentifier = new ArrayList<String>();
        }
        return this.uniformResourceIdentifier;
    }

    /**
     * Gets the value of the ipAddress property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the ipAddress property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIPAddress().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getIPAddress() {
        if (iPAddress == null) {
            iPAddress = new ArrayList<String>();
        }
        return this.iPAddress;
    }

    /**
     * Gets the value of the registeredID property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the registeredID property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRegisteredID().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getRegisteredID() {
        if (registeredID == null) {
            registeredID = new ArrayList<String>();
        }
        return this.registeredID;
    }

	/**
	 * Sets the value of the otherName property.
	 * 
	 * @param otherName the otherName to set
	 */
	public void setOtherName(final List<CredentialManagerOtherName> otherName) {
		this.otherName = otherName;
	}

	/**
	 * Sets the value of the rfc822Name property.
	 * 
	 * @param rfc822Name the rfc822Name to set
	 */
	public void setRfc822Name(final List<String> rfc822Name) {
		this.rfc822Name = rfc822Name;
	}

	/**
	 * Sets the value of the dNSName property.
	 * 
	 * @param dNSName the dNSName to set
	 */
	public void setDNSName(final List<String> dNSName) {
		this.dNSName = dNSName;
	}

	/**
	 * Sets the value of the x400Address property.
	 * 
	 * @param x400Address the x400Address to set
	 */
	public void setX400Address(final List<String> x400Address) {
		this.x400Address = x400Address;
	}

	/**
	 * Sets the value of the directoryName property.
	 * 
	 * @param directoryName the directoryName to set
	 */
	public void setDirectoryName(final List<String> directoryName) {
		this.directoryName = directoryName;
	}

	/**
	 * Sets the value of the ediPartyName property.
	 * 
	 * @param ediPartyName the ediPartyName to set
	 */
	public void setEdiPartyName(final List<CredentialManagerEdiPartyName> ediPartyName) {
		this.ediPartyName = ediPartyName;
	}

	/**
	 * Sets the value of the uniformResourceIdentifier property.
	 * 
	 * @param uniformResourceIdentifier the uniformResourceIdentifier to set
	 */
	public void setUniformResourceIdentifier(final List<String> uniformResourceIdentifier) {
		this.uniformResourceIdentifier = uniformResourceIdentifier;
	}

	/**
	 * Sets the value of the iPAddress property.
	 * 
	 * @param iPAddress the iPAddress to set
	 */
	public void setIPAddress(final List<String> iPAddress) {
		this.iPAddress = iPAddress;
	}

	/**
	 * Sets the value of the registeredID property.
	 * 
	 * @param registeredID the registeredID to set
	 */
	public void setRegisteredID(final List<String> registeredID) {
		this.registeredID = registeredID;
	}

}
