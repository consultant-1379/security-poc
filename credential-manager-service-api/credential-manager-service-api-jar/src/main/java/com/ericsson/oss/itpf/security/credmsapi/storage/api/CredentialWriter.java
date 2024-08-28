package com.ericsson.oss.itpf.security.credmsapi.storage.api;

import java.security.Key;
import java.security.cert.CRL;
import java.security.cert.Certificate;

import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

public interface CredentialWriter {

    /**
     * Store the certificate AND Private key into credential store
     * 
     * @param key
     *            Private key
     * @param cert
     *            Certificate
     * @param alias
     *            Alias of entry
     * @throws CredentialManagerPKIStoreException
     */
    
    void storeKeyPair(Key key, Certificate[] certificateChain, String alias) throws StorageException;
    
    /**
     * Store the trusted certificate in the
     * 
     * @param cert
     * @alias alias of entry
     * @throws CredentialManagerPKIStoreException
     */
    void addTrustedEntry(Certificate cert, String alias) throws StorageException;

    /**
     * @param crl
     * @throws StorageException
     */
    void addCrlEntry(CRL crl, String alias) throws StorageException;
    
    /**
     * 
     * @param alias
     * @throws StorageException
     */
    void deleteEntry(String alias) throws StorageException;

}
