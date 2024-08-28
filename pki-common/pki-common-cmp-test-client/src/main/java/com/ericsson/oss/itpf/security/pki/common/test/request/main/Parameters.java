package com.ericsson.oss.itpf.security.pki.common.test.request.main;

import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.request.WorkingMode;


public class Parameters {
    private String workingDirectory;
    private String vendorTrustedCA;
    private String nodeName;
    private String keyAlgorithm;
    private String signatureAlgorithm;
    private String transactionID;
    private String recipientSubjectDN;
    private String url;
    private String tlsCAPath;
    private String ipsecCAPath;

    private WorkingMode mode;
    private CertDataHolder entityCredential;

    private int keyLengthInRequest;
    private int validityInMinutes;
    private int postponeInMinutes;
    private int pvno;
    private int keySize;
    private int threadId;

    private boolean isSendTransactionID;
    private boolean isTLS;
    private boolean isValidProtectionAlgo = true;
    private boolean isValidHeader = true;
    private boolean isInDirectoryFormat = true;
    private boolean isValidRequestType = true;
    private boolean isValidKey = true;
    private boolean isValidProtectionBytes = true;
    private boolean isValidIAK = true;
    private boolean isNullProtectionAlgorithm = false;
    private boolean isNullSenderNonce = false;

    public boolean isNullSenderNonce() {
        return isNullSenderNonce;
    }

    public void setNullSenderNonce(final boolean isNullSenderNonce) {
        this.isNullSenderNonce = isNullSenderNonce;
    }

    public boolean isNullProtectionAlgorithm() {
        return isNullProtectionAlgorithm;
    }

    public void setNullProtectionAlgorithm(final boolean isNullProtectionAlgorithm) {
        this.isNullProtectionAlgorithm = isNullProtectionAlgorithm;
    }

    public boolean isValidIAK() {
        return isValidIAK;
    }

    public void setValidIAK(final boolean isValidIAK) {
        this.isValidIAK = isValidIAK;
    }

    public boolean isValidProtectionBytes() {
        return isValidProtectionBytes;
    }

    public void setValidProtectionBytes(final boolean isValidProtectionBytes) {
        this.isValidProtectionBytes = isValidProtectionBytes;
    }

    public boolean isValidKey() {
        return isValidKey;
    }

    public void setValidKey(final boolean isValidKey) {
        this.isValidKey = isValidKey;
    }

    public boolean isValidProtectionAlgo() {
        return isValidProtectionAlgo;
    }

    public void setValidProtectionAlgo(final boolean isValidProtectionAlgo) {
        this.isValidProtectionAlgo = isValidProtectionAlgo;
    }

    public boolean isValidRequestType() {
        return isValidRequestType;
    }

    public void setValidRequestType(final boolean isValidRequestType) {
        this.isValidRequestType = isValidRequestType;
    }

    public boolean isInDirectoryFormat() {
        return isInDirectoryFormat;
    }

    public void setInDirectoryFormat(final boolean isInDirectoryFormat) {
        this.isInDirectoryFormat = isInDirectoryFormat;
    }

    public boolean isValidHeader() {
        return isValidHeader;
    }

    public void setValidHeader(final boolean isValidHeader) {
        this.isValidHeader = isValidHeader;
    }

    public int getPvno() {
        return pvno;
    }

    public void setPvno(final int pvno) {
        this.pvno = pvno;
    }

    public String getWorkingDirectory() {
        return workingDirectory;
    }

    public void setWorkingDirectory(final String workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    public String getVendorTrustedCA() {
        return vendorTrustedCA;
    }

    public void setVendorTrustedCA(final String vendorTrustedCA) {
        this.vendorTrustedCA = vendorTrustedCA;
    }

    public String getNodeName() {
        return nodeName;
    }

    public void setNodeName(final String nodeName) {
        this.nodeName = nodeName;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(final String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(final int keySize) {
        this.keySize = keySize;
    }

    public int getThreadId() {
        return threadId;
    }

    public void setThreadId(final int threadId) {
        this.threadId = threadId;
    }

    public boolean isSendTransactionID() {
        return isSendTransactionID;
    }

    public void setSendTransactionID(final boolean isSendTransactionID) {
        this.isSendTransactionID = isSendTransactionID;
    }

    public String getRecipientSubjectDN() {
        return recipientSubjectDN;
    }

    public void setRecipientSubjectDN(final String recipientSubjectDN) {
        this.recipientSubjectDN = recipientSubjectDN;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }

    public CertDataHolder getEntityCredential() {
        return entityCredential;
    }

    public void setEntityCredential(final CertDataHolder vendorCred) {
        this.entityCredential = vendorCred;
    }

    public String getTlsCAPath() {
        return tlsCAPath;
    }

    public void setTlsCAPath(final String tlsCAPath) {
        this.tlsCAPath = tlsCAPath;
    }

    public String getIpsecCAPath() {
        return ipsecCAPath;
    }

    public void setIpsecCAPath(final String ipsecCAPath) {
        this.ipsecCAPath = ipsecCAPath;
    }

    public boolean isTLS() {
        return isTLS;
    }

    public void setTLS(final boolean isTLS) {
        this.isTLS = isTLS;
    }

    public int getKeyLengthInRequest() {
        return keyLengthInRequest;
    }

    public void setKeyLengthInRequest(final int keyLengthInRequest) {
        this.keyLengthInRequest = keyLengthInRequest;
    }

    public String getRecipientCA() {
        return isTLS ? tlsCAPath : ipsecCAPath;
    }

    public int getValidityInMinutes() {
        return validityInMinutes;
    }

    public void setValidityInMinutes(final int validityInMinutes) {
        this.validityInMinutes = validityInMinutes;
    }

    public int getPostponeInMinutes() {
        return postponeInMinutes;
    }

    public void setPostponeInMinutes(final int postponeInMinutes) {
        this.postponeInMinutes = postponeInMinutes;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(final String transactionID) {
        this.transactionID = transactionID;
    }

    public WorkingMode getMode() {
        return mode;
    }

    public void setMode(final WorkingMode mode) {
        this.mode = mode;
    }

}
