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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class CredentialManagerCRLIdentifier implements Serializable, Comparable<CredentialManagerCRLIdentifier> {

	//    private static final long serialVersionUID 

	/**
	 * 
	 */
	private static final long serialVersionUID = -7996061795373188698L;

	private String     issuerName;
	private Date       thisUpdate; 
	private Date       nextUpdate; 
	private byte[]     signature; 
	private BigInteger crlNumber; // optional field on CRL stuff


	/**
	 * Default constructor
	 */
	public CredentialManagerCRLIdentifier() {
		super();
	}


	/**
	 *  constructor that needs to have as input crl stuff 
	 */

	public CredentialManagerCRLIdentifier(final X509CRL crl) {
		super();
		issuerName = this.getIssuerName(crl);
		thisUpdate = this.getThisUpdate(crl);
		nextUpdate = this.getNextUpdate(crl);
		crlNumber  = this.getCrlNumber(crl);
		
		signature  = this.getSignature(crl);

	}


	/**
	 * @return the issuerName
	 */
	public String getIssuerName() {
		return issuerName;
	}


	/**
	 * @param issuerName the issuerName to set
	 */
	public void setIssuerName(final String issuerName) {
		this.issuerName = issuerName;
	}


	/**
	 * @return the thisUpdate
	 */
	public Date getThisUpdate() {
		return thisUpdate;
	}


	/**
	 * @param validFrom the validFrom to set
	 */
	public void setThisUpdate(final Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}


	/**
	 * @return the nextUpdate
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}


	/**
	 * @param nextUpdate the nextUpdate to set
	 */
	public void setNextUpdate(final Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}


	/**
	 * @return the signature
	 */
	public byte[] getSignature() {
		return signature;
	}


	/**
	 * @param signature the signature to set
	 */
	public void setSignature(final byte[] signature) {
		this.signature = signature;
	}


	/**
	 * @return the crlNumber
	 */
	public BigInteger getCrlNumber() {
		return crlNumber;
	}


	/**
	 * @param crlNumber the crlNumber to set
	 */
	public void setCrlNumber(final BigInteger crlNumber) {
		this.crlNumber = crlNumber;
	}


	/**
	 *  @param crl crl reference used to find other fields 
	 */

	private BigInteger  getCrlNumber(final X509CRL crl) {


		final Set<String> critSet = crl.getNonCriticalExtensionOIDs();
		ASN1Primitive extensionValue=null; 

		if (critSet != null && !critSet.isEmpty()) {
			//  		System.out.println("Set of Not critical extensions:");
			for (final String oid : critSet) {
				
				if ((Extension.cRLNumber.getId().contentEquals(oid))) {

					final byte[] encodedExtensionValue = crl.getExtensionValue(oid);

					if (encodedExtensionValue != null) {

						try {
							extensionValue = JcaX509ExtensionUtils.parseExtensionValue(encodedExtensionValue);

							return new BigInteger(extensionValue.toString());

						} catch (final IOException e) { //NOSONAR
							// TODO Auto-generated catch block
							e.printStackTrace(); 
						}

					}
				} // if ((Extension.cRLNumber.getId().contentEquals(oid))) {


			}
		}
		return null;
	
	

	}

	private String  getIssuerName(final X509CRL crl) {
	    final Map<String, String> dnOidMap = new HashMap<String, String>();
	        dnOidMap.put("2.5.4.4", "SURNAME");           // OID for SURNAME
	        dnOidMap.put("2.5.4.12", "T");                // OID for TITLE
	        dnOidMap.put("2.5.4.5", "SN");                // OID for SerialNUMBER
	        dnOidMap.put("2.5.4.42", "GIVENNAME");        // OID for GIVENNAME
	        dnOidMap.put("2.5.4.46", "DN");               // OID for DNQUALIFIER
	        
	        final X500Principal dn = new X500Principal(crl.getIssuerX500Principal().getName());
	        final String crlIssuerStr = dn.getName(X500Principal.RFC2253, dnOidMap);
	        return crlIssuerStr;
	}

	private Date  getThisUpdate(final X509CRL crl) {
		
		return crl.getThisUpdate(); 
		
	}

	private Date  getNextUpdate(final X509CRL crl) {

		return crl.getNextUpdate() ;

	}



	private byte[] getSignature(final X509CRL crl) {
		final byte[]  signature= crl.getSignature();


	/*	System.out.println("signature value is:") ;
		for(int i = 0; i < signature.length; i++)
		{
			if ( i%20 ==0) System.out.printf(" \n");
			System.out.printf("%02x", ++signature[i]);

		}
		System.out.print( " ");*/

		return signature; 

	}


	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((crlNumber == null) ? 0 : crlNumber.hashCode());
		result = prime * result
				+ ((issuerName == null) ? 0 : issuerName.hashCode());
		result = prime * result
				+ ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
		result = prime * result + Arrays.hashCode(signature);
		result = prime * result
				+ ((thisUpdate == null) ? 0 : thisUpdate.hashCode());
		return result;
	}



	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @SuppressWarnings("squid:S3776")
	@Override
	public boolean equals(final Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final CredentialManagerCRLIdentifier other = (CredentialManagerCRLIdentifier) obj;
		if (crlNumber == null) {
			if (other.crlNumber != null)
				return false;
        } else if (!crlNumber.equals(other.crlNumber)) {
			return false;
        }
		if (issuerName == null) {
			if (other.issuerName != null)
                return false;
        } else if (!issuerName.equals(other.issuerName)) {
			return false;
        }
		if (nextUpdate == null) {
            if (other.nextUpdate != null)
                return false;
        } else if (!nextUpdate.equals(other.nextUpdate)) {
            return false;
        }
        if (!Arrays.equals(signature, other.signature))
            return false;
		if (thisUpdate == null) {
			if (other.thisUpdate != null)
				return false;
		} else if (!thisUpdate.equals(other.thisUpdate)) {
			return false;
        }
		return true;
	}


	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(final CredentialManagerCRLIdentifier o) {

		// check on crlNumber
		if (crlNumber == null) {
			if (o.crlNumber != null) {
				return -1;
			}
		} else if (o.crlNumber == null) {
			return 1;
		} else {
			if (crlNumber.compareTo(o.crlNumber) != 0) {
				return -1;
			}
		}

		// check on thisUpdate 
		
		if (thisUpdate == null) {
			if (o.thisUpdate != null) {
				return -1; 
			}
		} else if (o.thisUpdate == null) {
			return 1;
		} else {
			if (thisUpdate.compareTo(o.thisUpdate) != 0) {
				return -1;
			}
		}
		
		// check on nextUpdate
		
		if (nextUpdate == null) {
			if (o.nextUpdate != null) {
				return -1; 
			}
		} else if (o.nextUpdate == null) {
			return 1;
		} else {
			if (nextUpdate.compareTo(o.nextUpdate) != 0) {
				return -1;
			}
		}
	
		// check on issuerName 
		
		if (issuerName == null) {
			if (o.issuerName != null) {
				return -1; 
			}
		} else if (o.issuerName == null) {
			return 1;
		} else {
			if (issuerName.compareTo(o.issuerName) != 0) {
				return -1;
			}
		}
			
		// check on signature

		if (signature == null) {
			if (o.signature != null) {
				return -1;
			} 
		} else if (o.signature == null) {
			return 1;
		} else {
			if (signature.length != o.signature.length) {
				return -1;
			}

			for (int i=0; i<signature.length; i++) {
				if (signature[i]!=o.signature[i]) {
					return -1;
				}
			}
		}

		return 0;
		
    }
}


