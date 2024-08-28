package com.ericsson.oss.itpf.security.credmsapi.storage.api;

import java.security.Key;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Set;

import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

/**
 * 
 * @author esagchr Sarang Chalikwar
 * 
 */
public interface CredentialReader {

    /**
     * Read the private key from credential store
     * 
     * @param alias
     *            Alias of a certificate
     * @return
     * @throws Exception
     */
    Key getPrivateKey(String alias) throws StorageException;

    /**
     * 
     * Get the list of certificate from credential store
     * 
     * @param alias
     *            certificate alias
     * @return
     * @throws Exception
     */
    Certificate[] getCertificateChain(String alias) throws StorageException;

    /**
     * 
     * Get the list of certificate from credential store
     * 
     * @param alias
     *            certificate alias
     * @return
     * @throws Exception
     */
    Certificate getCertificate(String alias) throws StorageException;

    /**
     * @param rootAlias
     *            the root alias
     * @return all the certificate with alias starting with rootAlias. All certificates if rootAlias is an empty string.
     * @throws StorageException
     */
    Set<Certificate> getAllCertificates(String rootAlias) throws StorageException;

    /**
     * 
     * @throws StorageException
     */
    //boolean hasMoreEntries() throws StorageException;

    /**
     * @param alias (if null or empty returns all the CRLs)
     * @return
     * @throws StorageException
     */
     Set<CRL> getCRLs(String alias) throws StorageException;

}
