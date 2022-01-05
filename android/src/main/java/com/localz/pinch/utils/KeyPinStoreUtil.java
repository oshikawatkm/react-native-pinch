package com.localz.pinch.utils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.io.File;
import java.io.FileInputStream;
import android.os.Environment;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import android.util.Base64;
// import org.apache.commons.codec.binary.Base64;

public class KeyPinStoreUtil {

    private static HashMap<String[], KeyPinStoreUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");

    //  private final String trustBase64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    public static synchronized KeyPinStoreUtil getInstance(String[] filenames) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (filenames != null && instances.get(filenames) == null) {
            instances.put(filenames, new KeyPinStoreUtil(filenames));
        }
        return instances.get(filenames);

    }

    private KeyPinStoreUtil(String[] filenames) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Create a KeyStore for our trusted CAs
        // String keyStoreType = KeyStore.getDefaultType();
        // KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        // keyStore.load(null, null);

        // for (String filename : filenames) {
            // InputStream caInput = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + filename + ".cer"));
            // Certificate ca;
            // try {
                // ca = cf.generateCertificate(caInput);
                // System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
            // } finally {
                // caInput.close();
            // }

            // keyStore.setCertificateEntry(filename, ca);
        // }

        // Create a TrustManager that trusts the CAs in our KeyStore
        System.out.println(filenames);
        // InputStream caInput = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/cert.cer"));
         String fileName = "cert.cer";
        File file = new File(Environment.getExternalStorageDirectory(), fileName);
        InputStream caInput = new BufferedInputStream(new FileInputStream(file));
        Certificate ca;
        try {
            ca = cf.generateCertificate(caInput);
            System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
        } finally {
            caInput.close();
        }
         // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("cert", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Tell the URLConnection to use a SocketFactory from our SSLContext
        // TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        // tmf.init(keyStore);

        String trustBase64 = toBase64(ca.getPublicKey().getEncoded());

        TrustManager[] trustAllCerts = new TrustManager[] { 
            new X509TrustManager() {     
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
                    
                    return new X509Certificate[0];
                } 
                public void checkClientTrusted( 
                    java.security.cert.X509Certificate[] certs, String authType) throws CertificateException {} 
                public void checkServerTrusted( 
                    java.security.cert.X509Certificate[] certs, String authType)  throws CertificateException {
                        X509Certificate cert = certs[0];
                        checkTrustCert(cert);
                }
                private void checkTrustCert(X509Certificate cert) throws CertificateException {
                    String base64 =toBase64(cert.getPublicKey().getEncoded());
                    // 正当な証明書では無いとbase64でチェックしマッチしないなら例外を送出する
                    if (!trustBase64.equals(base64)) {
                        throw new CertificateException("cert doesn`t match " + base64 + " / " + trustBase64 );
                    }
                }

            } 
        };
        sslContext.init(null, trustAllCerts, null);
    }

    public SSLContext getContext() {
        return sslContext;
    }

    public String toBase64(byte[] b) {
        String base64 = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(b);
            byte[] sha256byte = md.digest();
            base64 = Base64.encodeToString(sha256byte, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return base64;
    }
}