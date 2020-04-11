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
import java.security.*;
import java.io.*;
import java.security.cert.CertificateException;
import javax.net.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.ssl.SSLServerSocketFactory;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class HSserver {
    private SSLServerSocketFactory sslsockfactory;
    private SSLServerSocket serversock;
    private SSLSocket clientsock;
    private String version = "SSLv3";
    private int portnum = 1234;
    private int sessID;
    public int[] cCookie, sCookie;
    private static String[] availCiphersReceived;
    private String ver;
    
    private String ServerCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslserver.cer";
    private String keystorefilepath = "C:/Program Files/Java/jdk1.8.0_101/bin/keystore.pfx";
    private X509Certificate serverCert, clientCert;
    
    static byte[] clientHello, epms, PMS;
    private byte[] serverHelloMessage;
    private byte[] serverCertificateBytes;
    private byte[] certRequest, clientCertBytes;
    private byte[] hellodone;
    byte[] encryptedclientverifymsg;
    static byte[] MasterSecret;
    byte[] KeyBlock;
    byte[] serverivs;
    
    byte[] cWritekey, sWritekey, cMacSecret, sMacSecret;
    
    PublicKey serverpubk, clientpubk;
    PrivateKey serverPrK;
        
    private SSLContext context;
    private InputStream bytesin;
    private OutputStream bytesout;
    static SSLHandshake hsserver = new SSLHandshake();
    
     private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    public void Init() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException{
        context = hsserver.create_init_SSLContext(version, hsserver.KeyStoreFilePath);
        sslsockfactory = context.getServerSocketFactory();
        serversock = (SSLServerSocket)sslsockfactory.createServerSocket(portnum);
        System.out.println("Started up SSLServerSocket on port " + portnum + "...");
        clientsock = (SSLSocket)serversock.accept();
        System.out.println("Client connected.");
        bytesin = clientsock.getInputStream();
        bytesout = clientsock.getOutputStream();
    }
    
    byte[] rcvMsg () throws IOException{
        byte[] message = new byte[10000];
        bytesin.read(message);
        return message;
    }
    

    
    String ConvertBytetoString(byte[] bytemessage){
        StringBuilder bye = new StringBuilder();
        for (byte b: bytemessage){
            bye.append((char)b);
        }
        return bye.toString();
    }
    
    void processClientHello(String clienthello){
        //Processing each part of message split by ,
        String[] totalHello = clienthello.split(",");
        
        //version is the first part
        ver = totalHello[0];
        
        //session id is the second part
        sessID = Integer.parseInt(totalHello[1]);
        
        //cookie (random int[]) is the third part
        String[] totalCookie = totalHello[2].split(" ");
        
        cCookie = new int[totalCookie.length];
        for (int i = 0; i < totalCookie.length; i++){
            cCookie[i] = Integer.parseInt(totalCookie[i]);
        }
        
        //available ciphersuites is the fourth and last part
        String[] totalCiphers = totalHello[3].split("\n");
        availCiphersReceived = totalCiphers;
        
        System.out.println("Received parts of Client Hello: ");
        System.out.println("Client Version: " + ver + "\nSession ID: " + sessID);
        System.out.println("Client Cookie: ");
        for (int i = 0; i < cCookie.length; i++){
            if (i == cCookie.length-1){
                System.out.printf("%d",cCookie[i]);
            }
            else
            System.out.printf("%d, ",cCookie[i]);
        }
        System.out.println("\nReceived available ciphersuites: ");
        for (int i = 0; i <availCiphersReceived.length; i++){
            System.out.println(availCiphersReceived[i]);
        }
    }
    
    void SendSHello(String[] availcipher) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException{
        hsserver.serverHello(ver, availcipher);
        
        String msg = ver + ',' + sessID + ',';
        
        sCookie = hsserver.randomCookieGen();
        for (int i = 0; i < sCookie.length; i++){
            msg = msg + sCookie[i] + " ";
        }
        msg = msg + "," + hsserver.chosenCipher;
        
        System.out.println("This is the server's hello message: " + msg);
        serverHelloMessage = msg.getBytes();
        bytesout.write(serverHelloMessage);
    }
    
    void sendCertificate() throws CertificateException, IOException{
        serverCert = hsserver.generateX509cert(ServerCertificateFilePath);
        serverCertificateBytes = serverCert.getEncoded();
        bytesout.write(serverCertificateBytes);
        bytesout.flush();
    }
    
    void showMeYourCert() throws IOException{
        //String cCreq = hsserver.CertificateRequest(serverCert);
       String cCreq = "Give me your certificate!";
        System.out.println("This is the certificate request message to be sent to client: " + cCreq);
        certRequest = cCreq.getBytes();
        bytesout.write(certRequest, 0, certRequest.length);
        bytesout.flush();
    }
    
    void helloDone() throws IOException{
        String done = "Server done";
        hellodone = done.getBytes();
        bytesout.write(hellodone);
        bytesout.flush();
        System.out.println("Sent message to client: " + done);
    }
    
    X509Certificate receiveCert() throws IOException, CertificateException{
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytesin);
        clientCertBytes = clientCert.getEncoded();
        System.out.println("This is the received client certificate: " + clientCert.toString());
        return clientCert;
    }
    
     void generatePrivateKey(X509Certificate cert) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, InvalidKeySpecException{
        //TO DO: Generate key pair from given X509Certificate to be used in RSA asymmetric encryption/decrption for client/server verification/communication purposes.
        //loading keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        //really essentially I'm just accessing the keystore.jks file I have in
        //that KeyStoreFilePath file
        //....why yes, I made the password to my alias -testKey "password"....If you made it differently, then change this
        char[] password = "password".toCharArray();
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(keystorefilepath);
            keyStore.load(fis, password);            
        } finally {
            if (fis != null){
                fis.close();
            }
        }
       //serverPrK = (PrivateKey)keyStore.getKey("sslserver", password);
        String filepath = "pks_to_pem/ServerKey.pk8";
 
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Files.readAllBytes(Paths.get(filepath));
        String keystring = new String(keyBytes);
        keystring = keystring.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
//keyBytes = Base64.getDecoder().decode(keystring);
         keyBytes = DatatypeConverter.parseBase64Binary(keystring);
        System.out.println(keystring);
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(keyBytes);
        serverPrK = kf.generatePrivate(keySpecPKCS8);

        System.out.println("This is the server private key: " + serverPrK);
       serverpubk = cert.getPublicKey();
    }
     
     byte[] decryptRSAPrK(byte[] message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, NoSuchPaddingException, UnrecoverableKeyException, InvalidKeySpecException {
         generatePrivateKey(serverCert);
         Cipher RSACipher = Cipher.getInstance("RSA");
         RSACipher.init(DECRYPT_MODE, serverPrK);
         System.out.println("Size of encrypted message: " + message.length);
         byte[] decryptedmsg = RSACipher.update(message);
         return decryptedmsg;
     }
     
     byte[] decryptRSAPuK(byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
         PublicKey clientpubk = clientCert.getPublicKey();
         Cipher RSACipher = Cipher.getInstance("RSA");
         RSACipher.init(DECRYPT_MODE, clientpubk);
         byte[] decryptedmsg = RSACipher.update(input);
         return decryptedmsg;
     }
     
     void processClientVerify() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException{
 
        encryptedclientverifymsg = new byte[256];
        bytesin.read(encryptedclientverifymsg);

        System.out.println("encrypted message length: " + encryptedclientverifymsg.length);
        byte[] e_CVmsg = new byte[encryptedclientverifymsg.length];
        System.arraycopy(encryptedclientverifymsg, 0, e_CVmsg, 0, encryptedclientverifymsg.length);
        
        byte[] clientverifymsg = decryptRSAPuK(e_CVmsg);
     }
     
     void rcvChangeCipherSpec() throws IOException{
         byte [] changecipherspec = new byte[1];
         bytesin.read(changecipherspec);
         System.out.println("Change cipher spec msg content: "+(int)changecipherspec[0]);
         if (changecipherspec[0] == (byte)1){
             System.out.println("Change cipher spec message from client was received.");
         }
     }
     
     void rcvFinishedMsg() throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException{
         byte[] ivs = new byte[8];
         bytesin.read(ivs);
         byte[] encryptedmsg = new byte[40];
         bytesin.read(encryptedmsg);
         
         Cipher DeCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
         KeyBlock = hsserver.genKeyBlock(MasterSecret, cCookie, sCookie);
         cWritekey = new byte[24];
         System.arraycopy(KeyBlock, 40, cWritekey, 0, 24);
         SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
         DESedeKeySpec kspec = new DESedeKeySpec(cWritekey);
        SecretKey CWK = skf.generateSecret(kspec);
        IvParameterSpec IV = new IvParameterSpec(ivs);
        DeCipher.init(DECRYPT_MODE, CWK, IV);

         byte[] finishedmsg = DeCipher.update(encryptedmsg);
         System.out.println("Finished msg received from client: " + finishedmsg);
     }
     
     byte[] decryptMsg(byte[] encryptedmsg, byte[] ivs) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
         Cipher DeCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
          
         SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
         DESedeKeySpec kspec = new DESedeKeySpec(cWritekey);
        SecretKey CWK = skf.generateSecret(kspec);
        IvParameterSpec IV = new IvParameterSpec(ivs);
        DeCipher.init(DECRYPT_MODE, CWK, IV);

         byte[] decryptedmsg = DeCipher.doFinal(encryptedmsg);
         return decryptedmsg;
         
     }
     
     void ChangeCipherSpec() throws IOException {  
        byte message = 0x01;
        System.out.println("Change cipher spec message value sent to client: " + (int)message);
        bytesout.write(message);
    }
     
     void FinishedMessage(byte[] senderID, String cipher) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException{
         baos.write(clientHello);
        baos.write(serverHelloMessage);
        baos.write(serverCertificateBytes);
//        baos.write(certRequest);
        baos.write(hellodone);
//        baos.write(clientCertBytes);
//        baos.write(encryptedclientverifymsg);
        baos.write(epms);
        byte[] totalhsmessages = baos.toByteArray();
        baos.reset();
        
        byte[] md5hash = hsserver.generateFinishedMsg("MD5", MasterSecret, totalhsmessages, senderID);
        byte[] shahash = hsserver.generateFinishedMsg("SHA-1", MasterSecret, totalhsmessages, senderID);
        baos.write(md5hash);
        baos.write(shahash);
        byte[] finishedmsg = baos.toByteArray();
        baos.reset();
        
        byte[] encryptedfinishedmsg = encryptFinish(finishedmsg, cipher, MasterSecret);
        System.out.println("Encrypted finished message size: " + encryptedfinishedmsg.length);
        bytesout.write(serverivs);
        bytesout.write(encryptedfinishedmsg);
    }
     
     byte[] encryptFinish(byte[] message, String ciphertype, byte[] mastersecret) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, IOException{
        Cipher ciph = Cipher.getInstance(ciphertype);
        
        sWritekey = new byte[24];
        System.arraycopy(KeyBlock, 40, cWritekey, 0, 24);
        
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
        DESedeKeySpec kspec = new DESedeKeySpec(cWritekey);

        SecretKey CWK = skf.generateSecret(kspec);
        ciph.init(ENCRYPT_MODE, CWK);
        serverivs = ciph.getIV();
        System.out.println("Iv length: " + serverivs.length);
        
        return ciph.doFinal(message);
    }
     
     void receiveSSLMessage() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
         byte[] wholemsg = new byte[68];
         bytesin.read(wholemsg);
         byte[] ivs = new byte[8];
         bytesin.read(ivs);
         
         System.out.println("Whole Record Layer message received: " + wholemsg + "\nWhole message length: " +  wholemsg.length);
         int payloadlength = (int)wholemsg[3];
         byte[] pre_msg = new byte[payloadlength];
         

         //copy the non-header data.
         System.arraycopy(wholemsg, 4, pre_msg, 0, payloadlength);
         byte[] decrypted = decryptMsg(pre_msg, ivs);
         
         System.out.println("Decrypted msg: " + decrypted);
         
//         System.out.println("Decrypted message length: " + decrypted.length);
//         byte[] msgwithouthash = new byte[decrypted.length-20];
//         byte[] hash = new byte[20];
//         
//         System.arraycopy(decrypted, 0, msgwithouthash, 0, decrypted.length-20);
//         System.arraycopy(decrypted, decrypted.length-20, hash, 0, 20);
//         
//         String message = ConvertBytetoString(msgwithouthash);
//         System.out.println("This is the received Record Layer SSL message content from client: " + message);
//         
//         checkRLhash(msgwithouthash, hash);
//         
     }
     
     void checkRLhash(byte[] msgwithouthash, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException{
         cMacSecret = new byte[20];
         System.arraycopy(KeyBlock, 20, cMacSecret, 0, 20);
         Mac cMac = Mac.getInstance("HmacSHA1");
         
         SecretKeySpec cMacKey = new SecretKeySpec(cMacSecret, "HmacSHA1");
         cMac.init(cMacKey);
         
         byte[] hashcheck = cMac.doFinal(msgwithouthash);
         if (hashcheck.equals(hash)){
             System.out.println("The HMAC matches as expected from client mac secret.");
         }
     }
     
     void clearRcvbuffer() throws IOException{
         bytesin.read();
     }
    
    public static void main(String[]args)throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, InvalidAlgorithmParameterException, InvalidKeySpecException, InterruptedException{
        HSserver server = new HSserver();
        server.Init();
        
        /**SSL HANDSHAKE: part 1**/
        clientHello = server.rcvMsg();

        String clientshello = server.ConvertBytetoString(clientHello);
        System.out.println("This is the client hello received: "+ clientshello);
        server.processClientHello(clientshello);
        
        server.SendSHello(availCiphersReceived);
        
        /*SSL HANDSHAKE: part 2*/
        server.sendCertificate();
        server.showMeYourCert();
        server.helloDone();
        
        /*SSL HANDSHAKE: part 3*/
        //TODO: receive all client messages.
        //first message: client's X509 certificate
      //  server.receiveCert();
       // server.clearRcvbuffer();
        //second message: pre-master secret, encrypted in server's public key. Must decrypt with server's private key from server's X509Certificate.
        epms = new byte[256];
        server.bytesin.read(epms);

        byte[] PMS = server.decryptRSAPrK(epms);
        System.out.println("This is sparta: " + PMS);
        
//        Path path = Paths.get("cheatingtime.txt");
//        String spms = new String(Files.readAllBytes(path));
//        byte[] premastersecret = Base64.getDecoder().decode(spms);

 
        MasterSecret = hsserver.generateMasterSecret("Master Secret", PMS, server.cCookie, server.sCookie);
        System.out.println("This it the master secret produced by the server based on the received pre-master secret: " + server.ConvertBytetoString(MasterSecret));
        //Third message: clientverifymsg.
        //Verify client's certificate by decrypting clientverifymsg with client's public key from client's X509Certificate.
//        server.processClientVerify();
        
        
        /*SSL HANDSHAKE: part 4*/
        
        //receive client's change_cipher_spec message
        server.rcvChangeCipherSpec();
        //receive client's finished_message
        server.rcvFinishedMsg();
    
        
        //send change_cipher_spec; message contents is a single byte, value of '1'
        server.ChangeCipherSpec();

        //send finished_message = concat of two values: MD5hash size[16] and SHAhash size [20]
        //MD5(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        //SHA(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        server.FinishedMessage("server".getBytes(), "DESede/CBC/PKCS5Padding");
        
        //SSL Record Layer
        //header = 5 bytes
        //byte 0 = SSL Record type = SSL_R3_APPLICATION_DATA = 17 (in hex) (decimal = 23)
        //bytes 1-2 = SSL version = SSL3_VERSION = 0x0300
        //bytes 3-4 = datasize in payload (excluding this header itself)
        server.receiveSSLMessage();
    }
}
