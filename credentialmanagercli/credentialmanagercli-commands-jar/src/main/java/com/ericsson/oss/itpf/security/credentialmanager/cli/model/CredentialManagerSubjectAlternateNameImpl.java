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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName;

/**
 * 
 * @author ewagdeb
 * 
 */
public class CredentialManagerSubjectAlternateNameImpl implements
		CredentialManagerSubjectAltName {

	/**
     * 
     */
	private static final long serialVersionUID = 2542249818035074039L;
	private List<ALTERNATE_NAME_TYPE> type = new ArrayList<ALTERNATE_NAME_TYPE>();
	private List<List<String>> value = new ArrayList<List<String>>();
	private final Map<ALTERNATE_NAME_TYPE, List<String>> attributeNames = new HashMap<ALTERNATE_NAME_TYPE, List<String>>();
	private Attribute attribute;
	private String subjectAlternativeName = "";

	public CredentialManagerSubjectAlternateNameImpl(
			final Object subjectAlternateNameObj) {
		SubjectAlternativeNameType subjectAltName = null;

		if (subjectAlternateNameObj != null
				&& subjectAlternateNameObj instanceof SubjectAlternativeNameType) {
			subjectAltName = (SubjectAlternativeNameType) subjectAlternateNameObj;
			Map<ALTERNATE_NAME_TYPE, List<String>> subjAltAttributes = new HashMap<ALTERNATE_NAME_TYPE, List<String>>();
                        
                        if (!subjectAltName.getDirectoryname().isEmpty()) {
                                subjAltAttributes.put(ALTERNATE_NAME_TYPE.DIRECTORY_NAME, subjectAltName.getDirectoryname());
                                this.type.add(ALTERNATE_NAME_TYPE.DIRECTORY_NAME);
                                this.value.add(subjectAltName.getDirectoryname());
                        }

			if (!subjectAltName.getDns().isEmpty()) {
			        subjAltAttributes.put(ALTERNATE_NAME_TYPE.DNS, subjectAltName.getDns());
				this.type.add(ALTERNATE_NAME_TYPE.DNS);
				this.value.add(subjectAltName.getDns());
			}

			if (!subjectAltName.getEmail().isEmpty()) {
                                subjAltAttributes.put(ALTERNATE_NAME_TYPE.EMAIL, subjectAltName.getEmail());
				this.type.add(ALTERNATE_NAME_TYPE.EMAIL);
				this.value.add(subjectAltName.getEmail());
			}

			if (!subjectAltName.getIpaddress().isEmpty()) {
                                subjAltAttributes.put(ALTERNATE_NAME_TYPE.IP_ADDRESS, subjectAltName.getIpaddress());
				this.type.add(ALTERNATE_NAME_TYPE.IP_ADDRESS);
				this.value.add(subjectAltName.getIpaddress());
			}

			if (!subjectAltName.getRegisteredid().isEmpty()) {
                                subjAltAttributes.put(ALTERNATE_NAME_TYPE.REGISTERED_ID, subjectAltName.getRegisteredid());
				this.type.add(ALTERNATE_NAME_TYPE.REGISTERED_ID);
				this.value.add(subjectAltName.getRegisteredid());
			}

			if (!subjectAltName.getUri().isEmpty()) {
                                subjAltAttributes.put(ALTERNATE_NAME_TYPE.URI, subjectAltName.getUri());
				this.type.add(ALTERNATE_NAME_TYPE.URI);
				this.value.add(subjectAltName.getUri());
			}

			if (!subjectAltName.getOthername().isEmpty()) {
			        subjAltAttributes.put(ALTERNATE_NAME_TYPE.OTHER_NAME, subjectAltName.getOthername());
				this.type.add(ALTERNATE_NAME_TYPE.OTHER_NAME);
				this.value.add(subjectAltName.getOthername());
			}
			//this.attributeNames.put(this.type, this.value); //buggy behaviour in case of multiple attributes
			this.attributeNames.putAll(subjAltAttributes);
			generateAttribute();

		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerSubjectAlternateName#getType()
	 */
	@Override
	public List<ALTERNATE_NAME_TYPE> getType() {
		if (this.type == null) {
			this.type = new ArrayList<ALTERNATE_NAME_TYPE>();
			//being instantiated here type.size will be always 0
			if(this.value.size()-this.type.size() > 0) {
			    for(int i=0; i<this.value.size()-this.type.size(); i++) {
			        this.type.add(ALTERNATE_NAME_TYPE.NO_VALUE);
			    }
			}
		}
		return this.type;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerSubjectAlternateName
	 * #setType(com.ericsson.oss.itpf.security.cli.service.model.CredentialManagerSubjectAlternateNameBean
	 * .ALTERNATE_NAME_TYPE)
	 */
	@Override
	public void setType(final List<ALTERNATE_NAME_TYPE> type) {
		this.type = type;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerSubjectAlternateName#getValue()
	 */
	@Override
	public List<List<String>> getValue() {
		if (this.value == null) {
			this.value = new ArrayList<List<String>>();
			//being instantiated value.size will be always 0
			if(this.type.size()-this.value.size()>0) {
			    for(int i=0; i<this.type.size()-this.value.size(); i++) {
			        this.value.add(new ArrayList<String>());
			    }
			}
		}
		return this.value;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerSubjectAlternateName#setValue(java.util.List)
	 */
	@Override
	public void setValue(final List<List<String>> value) {
		this.value = value;
	}

	@Override
	public Attribute getAttribute() {

//		if (this.attribute == null) {
//			return new Attribute(null);
//		}
		return attribute;
	}

    private void generateAttribute() {
        final Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
        oids.add(Extension.subjectAlternativeName);
        final Vector<GeneralName> entries = new Vector<GeneralName>();

        for (final ALTERNATE_NAME_TYPE type : attributeNames.keySet()) {

            final List<String> values = attributeNames.get(type);

            if (type != null && type.equals(ALTERNATE_NAME_TYPE.DIRECTORY_NAME)) {
                for (final String val : values) {

                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "directoryName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.directoryName, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.DNS)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "dNSName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.dNSName, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.EMAIL)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "rfc822Name=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.rfc822Name, val);
                        entries.add(subjectAltName);
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.URI)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "uniformResourceIdentifier=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.uniformResourceIdentifier, val);
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.IP_ADDRESS)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "iPAddress=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.iPAddress, val);
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.OTHER_NAME)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "otherName=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.otherName, val);
                        entries.add((subjectAltName));
                    }
                }
            }
            if (type != null && type.equals(ALTERNATE_NAME_TYPE.REGISTERED_ID)) {
                for (final String val : values) {
                    if (val != null && !val.equals("")) {
                        subjectAlternativeName += "registeredID=" + val + ",";
                        final GeneralName subjectAltName = new GeneralName(GeneralName.registeredID, val);
                        entries.add((subjectAltName));
                    }
                }
            }
        }

        final GeneralName[] names = new GeneralName[entries.size()];
        entries.copyInto(names);

        final GeneralNames generalNames = new GeneralNames(names);

        final ExtensionsGenerator extGen = new ExtensionsGenerator();
        try {
            extGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
        } catch (final IOException e) {
            // TODO LOG ERROR
            e.printStackTrace();
        }

        final Extensions extensions = extGen.generate();
        attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
    }

    @Override
    public String getSubjectAlternativeName() {
        if (this.subjectAlternativeName.endsWith(",")) {
            this.subjectAlternativeName = this.subjectAlternativeName.substring(0, this.subjectAlternativeName.length() - 1);
        }
        return this.subjectAlternativeName;
    }
}