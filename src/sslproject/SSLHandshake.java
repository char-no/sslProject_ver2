/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sslproject;

/**
 *
 * @author SLam
 */

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.stream.IntStream;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import javax.net.ssl.*;


public class SSLHandshake {
    private String [] clientProtocols, serverCiphers, serverProtocols;
    public String [] availciphersuites;
    private String clientVersion = "SSLv3";
            private String serverVersion;
    public String chosenCipher;
    public int[] clientCookie;
    public int[] serverCookie;
    private int SessionID;
    String KeyStoreFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/keystore.jks";
    private String ServerCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslserver.cer";
    private String ClientCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslclient.cer";
    public X509Certificate serverCert, clientCert;
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    public byte[] client_macsecret, server_macsecret, client_writekey, server_writekey;

    void clientHello() throws NoSuchAlgorithmException, KeyManagementException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException {
       
        System.out.println("Client version: " + clientVersion);
        /*SSLContext creates an instance of SSL, from which we can generate things 
        such as the ciphersuites and SSL parameters needed for the handshake based on the
        preferred algorithms of the specific instance (computer/device) running the program.
        */
        SSLContext clientCont = create_init_SSLContext(clientVersion, KeyStoreFilePath);

        
        /*.getSupportedSSLParameters gets all supported SSL parameters; most of the cipher suites are TLS, but we're doing SSL.
        Therefore, I selected out of them the ones beginning with 'S' (they all are SSL algorithms) and put them as the
        cipher suites preferred for choice to be sent to the server*/
        SSLParameters sslparam = clientCont.getSupportedSSLParameters();
        String[] supportedCipherSuites = sslparam.getCipherSuites();
        
        /*Here is just a loop to find out how many SSL algorithms there are in the list,
        to fix the size of the availciphersuites[max] array*/
        int max = 0;

        System.out.println("\nSupported cipher suites: \n");
        for (int i = 0; i < supportedCipherSuites.length; i++){
        System.out.println(supportedCipherSuites[i]);
        if (supportedCipherSuites[i].charAt(0)=='S'){
                    max++;
                }
        }
        int index = 0;
        availciphersuites = new String[max];
        System.out.println("\n\n SSL cipher suites to be sent to server: ");

        for (int i = 0; i < supportedCipherSuites.length; i++){
            if (supportedCipherSuites[i].charAt(0)=='S'){
                    availciphersuites[index] = supportedCipherSuites[i];
                    System.out.println(availciphersuites[index]);
                    index++;
                }
        }
    
        
        
        /*generate a set of random numbers (cookie) and a session ID to send*/
        clientCookie = randomCookieGen();
        System.out.println("\n Client Cookie: ");
        for (int i = 0; i < clientCookie.length; i++){
            System.out.printf("%d ", clientCookie[i]);
        }
    }
    
    public SSLContext create_init_SSLContext(String version, String FilePath) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException{
        SSLContext sslcont = SSLContext.getInstance(version);
        
        //loading keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        
        //really essentially I'm just accessing the keystore.jks file I have in
        //that KeyStoreFilePath file
        //....why yes, I made the password to my alias -testKey "password"....If you made it differently, then change this
        char[] password = "password".toCharArray();
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(KeyStoreFilePath);
            keyStore.load(fis, password);            
        } finally {
            if (fis != null){
                fis.close();
            }
        }
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        
        KeyManager[] KManager = kmf.getKeyManagers();
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        
        TrustManager[] TManager = tmf.getTrustManagers();
        
                
        /*initializing the ssl context requires a key manager, trust manager, 
        and a securerandom; key manager and trust manager are generated from the keystore*/
        sslcont.init(KManager, TManager, new SecureRandom());
        return sslcont;
    }
    
    
    public String SelectCipher(String cVersion, String [] clientCiphers) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException{
        String chosen = "No cipher match.";
        SSLContext servercont = create_init_SSLContext(cVersion, KeyStoreFilePath);
        
        SSLParameters serverparam = servercont.getSupportedSSLParameters();
        serverCiphers = serverparam.getCipherSuites();
        serverProtocols = serverparam.getProtocols();
        
        for (int i = 0; i < serverProtocols.length; i++){
        System.out.println(serverProtocols[i]);
        }
        System.out.println("\nAvailable cipher suites: \n");
        for (int i = 0; i < serverCiphers.length; i++){
        System.out.println(serverCiphers[i]);
            for (String clientCipher : clientCiphers) {
                if (serverCiphers[i].charAt(0)=='S' && serverCiphers[i].equals(clientCipher)) {
                    chosen = clientCipher;
                    break;
                }
            }
            if(chosen.equals(serverCiphers[i])){
               break;
            }
        }
        System.out.println("This is the chosen cipher: " + chosen);
        return chosen;
        
    }
    
    void serverHello(String cVersion, String[] clientCiphers) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException{
        chosenCipher = SelectCipher(cVersion, clientCiphers);
        serverCert = generateX509cert(ServerCertificateFilePath);
        System.out.println("This is the server certificate: " + serverCert.toString());
    
    }
    
    public X509Certificate generateX509cert (String certFilePath) throws FileNotFoundException, CertificateException, IOException{
        InputStream IS = null;
        X509Certificate cert;
        try {
            IS = new FileInputStream(certFilePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)cf.generateCertificate(IS);
        } finally {
            if (IS != null){
                IS.close();
            }
        }
        return cert;
    }
    
    void checkCertificate(X509Certificate cert) throws CertificateExpiredException, CertificateNotYetValidException, CertificateParsingException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException{
        cert.checkValidity();
        cert.getIssuerAlternativeNames();
        cert.getIssuerDN();
        
        PublicKey VerifyCertKey = cert.getPublicKey();
        try{
        cert.verify(VerifyCertKey);
        } finally {
            System.out.println("Certificate has been verified.");
        }
    }
    
    String CertificateRequest(X509Certificate scert){
        String certTypes = scert.getType();
        String supportedSigAlgs = scert.getSigAlgName();
        String certAuthorities = scert.getIssuerDN().getName();
        
        System.out.println("Certificate Type: " + certTypes);
        System.out.println("Supported Signature Algorithms: " + supportedSigAlgs);
        System.out.println("Certificate Authorities: " + certAuthorities);
        
        String creq = certTypes + "," + supportedSigAlgs + "," + certAuthorities;
        
        return creq;
    }
    
    void HelloDone(){
        String done = "Server Hello Done.";
        System.out.println(done);
    }
    
    public byte[] generatePreMasterSecret(X509Certificate cert){
        SecureRandom rando = new SecureRandom();
        byte protocolVersion[] = new byte[2];
        byte base[] = new byte[1];
        System.arraycopy(base, 0, protocolVersion, 0, base.length);
        byte pV[] = new byte[1];
        pV[0] = (byte)cert.getVersion();
        System.arraycopy(pV, 0, protocolVersion, 1, pV.length);
        
        byte [] restof46bytes = new byte[46];
        rando.nextBytes(restof46bytes);
        
        byte [] PMSecret = new byte[48];
        
        System.arraycopy(protocolVersion, 0, PMSecret, 0, protocolVersion.length);
        System.arraycopy(restof46bytes, 0, PMSecret, (48-restof46bytes.length), restof46bytes.length);
        
        return PMSecret;
    }
    
    void clientCertificategen() throws CertificateException, IOException{
        clientCert = generateX509cert(ClientCertificateFilePath);
    }
    
    byte[] RSAencrypt(byte[] input, X509Certificate cert) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher RSACipher = Cipher.getInstance("RSA");
        PublicKey PK = cert.getPublicKey();
        RSACipher.init(ENCRYPT_MODE, PK);
        return RSACipher.doFinal(input);      
    }
    
    byte[] generateMasterSecret(String type, byte[]secret, int[]clientRandom, int[]serverRandom) throws NoSuchAlgorithmException, IOException{
        
        /* master_secret = MD5(pre_master_secret + SHA('A' + pre_master_secret + ClientHello.random + ServerHello.random)) 
        + MD5(pre_master_secret + SHA('BB' + pre_master_secret + ClientHello.random + ServerHello.random)) 
        + MD5(pre_master_secret + SHA('CCC' + pre_master_secret + ClientHello.random + ServerHello.random));*/
        
        ///HOH BOY
        byte[] part1 = md5andshaprocessing("AA", secret, clientRandom, serverRandom);
        byte[] part2 = md5andshaprocessing("BB", secret, clientRandom, serverRandom);
        byte[] part3 = md5andshaprocessing("CCC", secret, clientRandom, serverRandom);
        
        /* using ByteArrayOutputStream to concatenate the 3 parts */
        
        baos.write(part1);
        baos.write(part2);
        baos.write(part3);
        
        byte[] result = baos.toByteArray();

        System.out.println("The " + type + " is indeed 48 bytes: " + result.length);
        System.out.println(type + " to string: " + Base64.getEncoder().encodeToString(result) + "\n");
        
        baos.reset();
        
        return result;
    }
    
    void genKeyBlock(byte[] mastersecret, int[]clientRandom, int[]serverRandom) throws NoSuchAlgorithmException, IOException{
        //SHA-1 mac length = 20; sha mac key length = 20
        //20 bytes client MAC secret
        //20 bytes server MAC secret
        
        //3DES_EDE_CBC = 24 bytes per key
        //24 bytes client write key
        //24 bytes server write key
        
        //Note: each hash part is 16 bytes, 16x6 = 96
        //We need 20 + 20 + 24 + 24 = 88 bytes in total, so we need 6 parts. (96 is closest we can get to 88).
        byte[] part1 = md5andshaprocessing("AA", mastersecret, clientRandom, serverRandom);
        byte[] part2 = md5andshaprocessing("BB", mastersecret, clientRandom, serverRandom);
        byte[] part3 = md5andshaprocessing("CCC", mastersecret, clientRandom, serverRandom);
        byte[] part4 = md5andshaprocessing("DDDD", mastersecret, clientRandom, serverRandom);
        byte[] part5 = md5andshaprocessing("EEEEE", mastersecret, clientRandom, serverRandom);
        byte[] part6 = md5andshaprocessing("FFFFFF", mastersecret, clientRandom, serverRandom);
        
        baos.write(part1);
        baos.write(part2);
        baos.write(part3);
        baos.write(part4);
        baos.write(part5);
        baos.write(part6);
        
        byte[] keyblock = baos.toByteArray();
        baos.reset();
        
        client_macsecret = new byte[20];
        server_macsecret = new byte[20];
        client_writekey = new byte[24];
        server_writekey = new byte[24];
        
        System.arraycopy(keyblock, 0, client_macsecret, 0, 20);
        System.arraycopy(keyblock, 20, server_macsecret, 0, 20);
        System.arraycopy(keyblock, 40, client_writekey, 0, 24);
        System.arraycopy(keyblock, 64, server_writekey, 0, 24);
    }
    
    byte[] md5andshaprocessing(String alphabets, byte[]secret, int[]clientRandom, int[]serverRandom) throws NoSuchAlgorithmException, IOException{
        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        
        int partnum = 0;
        switch (alphabets.charAt(0)){
            case 'A': 
                partnum = 1;
                baos.write((byte)'A');
                break;
            case 'B': 
                partnum = 2;
                baos.write(alphabets.getBytes());
                break;
            case 'C': 
                partnum = 3;
                baos.write(alphabets.getBytes());
                break;
            case 'D': 
                partnum = 4;
                baos.write(alphabets.getBytes());
                break;
            case 'E': 
                partnum = 5;
                baos.write(alphabets.getBytes());
                break;
            case 'F':
                partnum = 6;
                baos.write(alphabets.getBytes());
                break;
            }
        baos.write(secret);
        for(int i = 0; i < clientRandom.length; i++){
        baos.write((byte)clientRandom[i]);
        }
         for(int i = 0; i < serverRandom.length; i++){
        baos.write((byte)serverRandom[i]);
        }
        byte [] beforesha = baos.toByteArray();       
        byte[] shapart = sha.digest(beforesha);
        
       /* System.out.println(beforesha + "\nwoopie: " + shapart);   
        
        System.out.println("Sha part " + partnum + " length: " + shapart.length);*/
        
        baos.reset();
        
        baos.write(secret);
        baos.write(shapart);
        
        byte [] beforemd5 = baos.toByteArray();
        byte[] wholepart = md.digest(beforemd5);
        
        System.out.println("Before processing with md5" + beforemd5 + "\nAfter processing with md5: " + wholepart);      
        System.out.println("Part " + partnum + " length: " + wholepart.length);
 
        baos.reset();
        return wholepart;
    }
    
    byte[] clientVerifyHash(String HashType, byte[] mastersecret, byte[] handshakemessages) throws NoSuchAlgorithmException, IOException{
        //md5_hash = MD5(master_secret + pad2 + MD5(handshake_messages + master_secret + pad1));   
        //type = MD5 or SHA-1
        MessageDigest hasher = MessageDigest.getInstance(HashType);
        
        int padsize = 1;
        
        switch(HashType){
            case "MD5": 
                padsize = 48;
                break;
            case "SHA-1":
                padsize = 40;
                break;
        }
        
        byte[] pad1 = new byte[padsize];
        byte[] pad2 = new byte[padsize];
        
        for (int i = 0; i < padsize; i++){
            pad1[i] = (0x36);
            pad2[i] = (0x5C);
        }
        
        baos.write(handshakemessages);
        baos.write(mastersecret);
        baos.write(pad1);
        
        byte[] before_HSM = baos.toByteArray();
        byte[] hashedHSM = hasher.digest(before_HSM);
        
        baos.reset();
        
        baos.write(mastersecret);
        baos.write(pad2);
        baos.write(hashedHSM);
        
        byte[] before_complete = baos.toByteArray();
        byte[] whole_hash = hasher.digest(before_complete);
        
        baos.reset();
        
        System.out.println("This is the client certificate verification: " + Base64.getEncoder().encodeToString(whole_hash));
        
        return whole_hash;
    }
    
      
    byte[] generateFinishedMsg(String HashType, byte[] mastersecret, byte[] handshakemessages, byte[] senderID) throws NoSuchAlgorithmException, IOException{
        //MD5(mastersecret + pad2 + MD5(hsmessages + senderid + mastersecret + pad1))
        //SHA(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        //HashType is a value of either MD5 or SHA-1; The finished message is a concatenation of the values of the hash equations mentioned above.
        
        MessageDigest hasher = MessageDigest.getInstance(HashType);
        
        int padsize = 1;
        
        switch(HashType){
            case "MD5": 
                padsize = 48;
                break;
            case "SHA-1":
                padsize = 40;
                break;
        }
        
        byte[] pad1 = new byte[padsize];
        byte[] pad2 = new byte[padsize];
        
        for (int i = 0; i < padsize; i++){
            pad1[i] = (0x36);
            pad2[i] = (0x5C);
        }
        
        baos.write(handshakemessages);
        baos.write(senderID);
        baos.write(mastersecret);
        baos.write(pad1);
        
        byte[] part1_prehash = baos.toByteArray();
        byte[] part1 = hasher.digest(part1_prehash);
        
        baos.reset();
        baos.write(mastersecret);
        baos.write(pad2);
        baos.write(part1);
        
        byte[] whole_prehash = baos.toByteArray();
        byte[] wholehash = hasher.digest(whole_prehash);
        
        baos.reset();
        
        System.out.println("This is the " + HashType + " hash of the finished message: " + wholehash);
        System.out.println(HashType + " hash size: " + wholehash.length);
        return wholehash;
    }
 
    
    /*Generates a set of random numbers*/
    public int[] randomCookieGen(){
        SecureRandom secrand = new SecureRandom();
        IntStream cookie = secrand.ints(128);
        return cookie.toArray();
    }
    
    /*Generates a random number for the session ID*/
    public int generateSessionID(){
        SecureRandom randsession = new SecureRandom();
       return randsession.nextInt(1234567890);
    }
    
    public static void main(String [] args) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException, CertificateExpiredException, CertificateNotYetValidException, CertificateParsingException, InvalidKeyException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        SSLHandshake client = new SSLHandshake();
        client.clientHello();
        SSLHandshake server = new SSLHandshake();
        //server.serverHello(client.clientVersion, client.availciphersuites, client.SessionID);
        client.checkCertificate(server.serverCert);
        server.CertificateRequest(server.serverCert);
        server.HelloDone();
        
        byte [] client_PMSecret = client.generatePreMasterSecret(server.serverCert);
        String pmsecret = Base64.getEncoder().encodeToString(client_PMSecret);
        System.out.println("This is the generated pre-master secret (by client): " + pmsecret);
        System.out.println("PM secret size: " + client_PMSecret.length);
        
        byte[] encryptedPMSecret = client.RSAencrypt(client_PMSecret, server.serverCert);
        System.out.println("This is the encrypted pre-master secret generated by the client: " + encryptedPMSecret + "\n");
        
       byte[] MasterSecret = client.generateMasterSecret("Master Secret", client_PMSecret, server.serverCookie, client.clientCookie);
       
       byte[] KeyBlock = client.generateMasterSecret("Key Block", MasterSecret, client.clientCookie, server.serverCookie);
    }
}
