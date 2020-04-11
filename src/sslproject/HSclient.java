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
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import static sslproject.HSserver.hsserver;

public class HSclient {
    private static SSLSocket clientsock;
    private SSLSocketFactory sslsockfactory;
    private String version = "SSLv3";
    private int portnum = 1234;
    private SSLContext context;
    static  SSLHandshake client = new SSLHandshake();
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private InputStream bytesin;
    private InputStream inputstr;
    private OutputStream bytesout;
    private int sessionID;
    public int[] servercookie, clientcookie;
    byte[] cWritekey, sWritekey, cMacSecret, sMacSecret;
    
    
    PublicKey clientPubK;
    PublicKey serverPubK;
    KeyPair clientKPair;
    PrivateKey clientPrK;
    
    
    private String chosenCipherSuite;
    
    private X509Certificate serverCert, clientCert;
        private String ClientCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslclient.cer";
    String keyfilepath = "pks_to_pem/clientKey.pem";
    String KeyFP = "C:/Program Files/Java/jdk1.8.0_101/bin/clientKey.p12";
    static byte[] clientHelloMessage, serverhello, sCertBytes, certReq, cCertBytes, hellodone, PMS, mastersecret, hsmessages, clientverifymsg, totalhsmessages;
    byte[] keyBlock;
    byte[] clientivs;
    
    public void Init() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException{
        context = client.create_init_SSLContext(version, client.KeyStoreFilePath);
        sslsockfactory = context.getSocketFactory();
        clientsock = (SSLSocket)sslsockfactory.createSocket("127.0.0.1", portnum);
        System.out.println("Successfully connected to server at port " + portnum + ".");
        bytesin = clientsock.getInputStream();
        bytesout = clientsock.getOutputStream();
    }
    
    public void ClientSendHello(SSLSocket CS)throws NoSuchAlgorithmException, KeyManagementException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException {
        client.clientHello();
        sessionID = client.generateSessionID();
        System.out.println("\nSession ID: " + sessionID);
        
        String message = version + "," + sessionID + ",";
        
        clientcookie = client.clientCookie;
        for (int i = 0; i < client.clientCookie.length; i++){
            message = message + client.clientCookie[i] + " ";
        }
        message = message + ",";
        for (int i = 0; i < client.availciphersuites.length; i++){
            message += client.availciphersuites[i] + '\n';
        }
        
        System.out.println("This is the client hello message: " + message);
        clientHelloMessage = message.getBytes();
        
        bytesout.write(clientHelloMessage);
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
    
    void processServerHello(String message) throws IOException{
        //Processing each part of message split by ,
        String[] totalHello = message.split(",");
        
        //version is the first part
        String ver = totalHello[0];
        
        //session id is the second part
        int sID = Integer.parseInt(totalHello[1]);
        if (sID == sessionID){
            System.out.println("The session ID matches and is correct.");
        }
        else{
            System.out.println("Wrong session ID. Bad. Terrible.");
            clientsock.close();
        }
        
        
        //cookie (random int[]) is the third part
        String[] totalCookie = totalHello[2].split(" ");
        
        servercookie = new int[totalCookie.length];
        for (int i = 0; i < totalCookie.length; i++){
            servercookie[i] = Integer.parseInt(totalCookie[i]);
        }
        
        //available ciphersuites is the fourth and last part
        chosenCipherSuite = totalHello[3];
        
        System.out.println("Received parts of Server Hello: ");
        System.out.println("Client Version: " + ver + "\nSession ID: " + sID);
        System.out.println("Client Cookie: ");
        for (int i = 0; i < servercookie.length; i++){
            if (i == servercookie.length-1){
                System.out.printf("%d",servercookie[i]);
            }
            else
            System.out.printf("%d, ",servercookie[i]);
        }
        System.out.println("\nChosen ciphersuite: " + chosenCipherSuite);
    }
    
    X509Certificate receiveCert() throws IOException, CertificateException{
        
        serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytesin);
        sCertBytes = serverCert.getEncoded();
        System.out.println("This is the received server certificate: " + serverCert.toString());

        return serverCert;
    }
    
    void waitForHelloFinish() throws IOException{
        hellodone = new byte[30];
        bytesin.read(hellodone, 0, 30);
        String hd = ConvertBytetoString(hellodone);
        System.out.println(hd);
    }
    
    void rcvCertReq() throws IOException{
        certReq = new byte[256];
        bytesin.read(certReq, 0, 256);
        String cr = ConvertBytetoString(certReq);
        System.out.println("Received certificate request: " + cr);
    }
    
    void sendCertificate() throws CertificateException, IOException{
        
        clientCert = client.generateX509cert(ClientCertificateFilePath);
        System.out.println("This is the client certificate: " + clientCert.toString());
        cCertBytes = clientCert.getEncoded();
        bytesout.write(cCertBytes);
    }
    
    void sendPreMasterSecret() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        PMS = client.generatePreMasterSecret(serverCert);
        byte[] PMSencrypted = client.RSAencrypt(PMS, serverCert);
        System.out.println("encrypted pre-master secret length: " + PMSencrypted.length);
        //bytesout.write(PMSencrypted);
        bytesout.write(PMS);
    }
    
    void sendClientVerify() throws IOException, NoSuchAlgorithmException, FileNotFoundException, CertificateException, KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, InvalidKeySpecException, URISyntaxException {
        baos.write(clientHelloMessage);
        baos.write(serverhello);
        baos.write(sCertBytes);
        baos.write(certReq);
        baos.write(hellodone);        
        baos.write(cCertBytes);
        baos.write(PMS);
        hsmessages = baos.toByteArray();
        
        baos.reset();
        
        mastersecret = client.generateMasterSecret("Master Secret", PMS, clientcookie, servercookie);
        

        byte[] CVmd5 = client.clientVerifyHash("MD5", mastersecret, hsmessages);
        byte[] CVsha = client.clientVerifyHash("SHA-1", mastersecret, hsmessages);
        
        baos.write(CVmd5);
        baos.write(CVsha);
        
        clientverifymsg = baos.toByteArray();
        
        baos.reset();

        
        //TO DO: encrypt clientverifymsg using client's private key from client's X509Certificate and send encrypted message to server.
                readPrivateKey();
                System.out.println("Private key: " + clientPrK.toString() + clientPrK.getFormat() + clientPrK.getAlgorithm());
                clientverifymsg = privatekeyRSAencrypt(clientverifymsg, clientPrK);
                System.out.print("This is the encrypted message to be sent: " + clientverifymsg);
                System.out.println("The length of the message: " + clientverifymsg.length);
                bytesout.write(clientverifymsg);
        
    }
    
    void readPrivateKey() throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, InvalidKeySpecException, URISyntaxException{
        //TO DO: Generate key pair from keystore to be used in RSA asymmetric encryption/decrption for client/server verification/communication purposes.
        //loading keystore
//        byte[] keybytes = Files.readAllBytes(Paths.get("pks_to_pem/cK.txt"));
//        String keystring = ConvertBytetoString(keybytes);
//        keystring = keystring.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
//        
//        keybytes = Base64.getDecoder().decode(keystring);

//        //keybytes = Base64.getDecoder().decode(keystring);
//        keybytes = keystring.getBytes();
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//       clientPrK = kf.generatePrivate(keySpec);


 //       privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
        String filepath = "pks_to_pem/ClientKey.pk8";
 
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Files.readAllBytes(Paths.get(filepath));
        String keystring = new String(keyBytes);
        keystring = keystring.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
//keyBytes = Base64.getDecoder().decode(keystring);
         keyBytes = DatatypeConverter.parseBase64Binary(keystring);
        System.out.println(keystring);
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(keyBytes);
        clientPrK = kf.generatePrivate(keySpecPKCS8);

        System.out.println("This is the client private key: " + clientPrK);

    }
    
    byte[] privatekeyRSAencrypt(byte[] message, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
         Cipher RSACipher = Cipher.getInstance("RSA");
        RSACipher.init(ENCRYPT_MODE, key);
        return RSACipher.doFinal(message);
    }
    
    void ChangeCipherSpec() throws IOException {  
        byte message = (byte)1;
        System.out.println("Change cipher spec message sent to server.");
        bytesout.write(message);
    }
    
    void rcvChangeCipherSpec() throws IOException{
         byte [] changecipherspec = new byte[1];
         bytesin.read(changecipherspec);
         System.out.println("Change cipher spec msg content: "+(int)changecipherspec[0]);
         if (changecipherspec[0] == (byte)1){
             System.out.println("Change cipher spec message from server was received.");
         }
     }
    
    void FinishedMessage(byte[] senderID, String cipher) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException{
        baos.write(clientHelloMessage);
        baos.write(serverhello);
        baos.write(sCertBytes);
        baos.write(certReq);
        baos.write(hellodone);        
  //      baos.write(cCertBytes);
        baos.write(PMS);

//        baos.write(clientverifymsg);
        totalhsmessages = baos.toByteArray();
        baos.reset();
        
        byte[] md5hash = client.generateFinishedMsg("MD5", mastersecret, totalhsmessages, senderID);
        byte[] shahash = client.generateFinishedMsg("SHA-1", mastersecret, totalhsmessages, senderID);
        baos.write(md5hash);
        baos.write(shahash);
        byte[] finishedmsg = baos.toByteArray();
        baos.reset();
        
        byte[] encryptedfinishedmsg = encryptMsg(finishedmsg, cipher, mastersecret);
        System.out.println("Encrypted finished message size: " + encryptedfinishedmsg.length);
        bytesout.write(clientivs);
        bytesout.write(encryptedfinishedmsg);
    }
    
    void rcvFinishedMsg() throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException{
         byte[] ivs = new byte[8];
         bytesin.read(ivs);
         byte[] encryptedmsg = new byte[40];
         bytesin.read(encryptedmsg);
         
         Cipher DeCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
         
         sWritekey = new byte[24];
         System.arraycopy(keyBlock, 64, sWritekey, 0, 24);
         SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
         DESedeKeySpec kspec = new DESedeKeySpec(sWritekey);
        SecretKey SWK = skf.generateSecret(kspec);
        IvParameterSpec IV = new IvParameterSpec(ivs);
        DeCipher.init(DECRYPT_MODE, SWK, IV);

         byte[] finishedmsg = DeCipher.update(encryptedmsg);
         System.out.println("Finished msg received from server: " + finishedmsg);
     }
    
    void ByteArrayToFile(byte[] byteArray) throws IOException{
        File myfile = new File("cheatingtime.txt");
        if(myfile.createNewFile()){
            System.out.println("File created.");
        }

        FileWriter fw = new FileWriter(myfile, false);
        fw.write(Base64.getEncoder().encodeToString(byteArray));
    }
    
    byte[] encryptMsg(byte[] message, String ciphertype, byte[] mastersecret) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, IOException{
        Cipher ciph = Cipher.getInstance(ciphertype);
        keyBlock = client.genKeyBlock(mastersecret, clientcookie, servercookie);
        
        cWritekey = new byte[24];
        System.arraycopy(keyBlock, 40, cWritekey, 0, 24);
        
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
        DESedeKeySpec kspec = new DESedeKeySpec(cWritekey);

        SecretKey CWK = skf.generateSecret(kspec);
        ciph.init(ENCRYPT_MODE, CWK);
        clientivs = ciph.getIV();
        System.out.println("Iv length: " + clientivs.length);
        
        return ciph.doFinal(message);
    }
    
    void RLsendmessage(String msg) throws NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException{
        Mac cMac = Mac.getInstance("HmacSHA1");
        cMacSecret = new byte[20];
        
        //client_macsecret is first 20 bytes of keyblock
        System.arraycopy(keyBlock, 0, cMacSecret, 0, 20);
        SecretKeySpec cMacKey = new SecretKeySpec(cMacSecret, "HmacSHA1");
        cMac.init(cMacKey);
        
        byte[] hash = cMac.doFinal(msg.getBytes());
        
        baos.write(msg.getBytes());
        baos.write(hash);
        
        byte[] msg_preEncr = baos.toByteArray();
        baos.reset();
        byte[] enc_msg = encryptMsg(msg_preEncr, "DESede/CBC/PKCS5Padding", mastersecret);
        byte[] SSLHeader = produceSSLRecordHeader(enc_msg);
        
      
        
        baos.write(SSLHeader);
        baos.write(enc_msg);
        
        byte[] msgtosend = baos.toByteArray();
        baos.reset();
        
        bytesout.write(msgtosend);
        bytesout.write(clientivs);
        System.out.println("Client sending message to server: (SSLRECORDLAYER) " + msg);
        System.out.println("Whole datapacket length: " + msgtosend.length);
    }
    
    byte[] produceSSLRecordHeader(byte[] encryptedmsg) throws IOException{
        //SSLRecordType = 23 = Application Layer
        byte SSLRecordType = (byte)23;
        byte[] SSLVersion = {(byte)0x03, (byte)0x00};
        byte msglength = (byte)encryptedmsg.length;
        baos.write(SSLRecordType);
        baos.write(SSLVersion);
        baos.write(msglength);
        
        byte[] SSLRecordHeader = baos.toByteArray();
        baos.reset();
        return SSLRecordHeader;
    }
    
    void clearbuffer() throws IOException{
        bytesout.write("Clear this please".getBytes());
        bytesout.flush();
    }
    
    
    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, InvalidKeySpecException, URISyntaxException, InvalidAlgorithmParameterException{
        HSclient hsclient = new HSclient();
        hsclient.Init();
        
        /**SSL HANDSHAKE: part 1**/
        hsclient.ClientSendHello(clientsock);
        serverhello = hsclient.rcvMsg();
        
        String sHi = hsclient.ConvertBytetoString(serverhello);
        System.out.println("Received server hello message, unprocessed: " + sHi);
        hsclient.processServerHello(sHi);
        
        /*SSL HANDSHAKE: part 2*/
        hsclient.receiveCert();
        hsclient.rcvCertReq();
        hsclient.waitForHelloFinish();
        
        /*SSL HANDSHAKE: part 3*/
      //  hsclient.sendCertificate();
        //hsclient.clearbuffer();
        hsclient.sendPreMasterSecret();
       hsclient.mastersecret = client.generateMasterSecret("Master Secret", PMS, hsclient.clientcookie, hsclient.servercookie);
        
        System.out.println("This is the client's master secret: " + hsclient.ConvertBytetoString(hsclient.mastersecret));
        
        //TO DO: finish up sendClientVerify() 
//        hsclient.sendClientVerify();

        
        /*SSL HANDSHAKE: part 4*/
       String ciphertype = "DESede/CBC/PKCS5Padding";
       
        //send change_cipher_spec; message contents is a single byte, value of '1'
        hsclient.ChangeCipherSpec();
        
        
        //send finished_message = concat of two values: MD5hash size[16] and SHAhash size [20]
        //MD5(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        //SHA(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        hsclient.FinishedMessage("client".getBytes(), ciphertype);
        
        //receive server's change_cipher_spec message
        hsclient.rcvChangeCipherSpec();
        //receive server's finished_message
        hsclient.rcvFinishedMsg();
        
        //SSL Record Layer
        //SSL Record Header = 5 bytes
        //byte 0 = SSL Record type = SSL_R3_APPLICATION_DATA = 17 (in hex) (decimal = 23)
        //bytes 1-2 = SSL version = SSL3_VERSION = 0x0300
        //bytes 3-4 = datasize in payload (excluding this header itself)
        hsclient.RLsendmessage("Hi my guy! This is the record layer.");

    }
    
}
