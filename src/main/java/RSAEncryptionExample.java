package com.example.demo;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.util.Base64;

public class RSAEncryptionExample {

    public static void main(String[] args) throws Exception {

        // Genera una chiave RSA a 3200 bit
        //KeyPairGenerator kpg = createKeyPairGenerator ();
        //KeyPair kp = creaKeyPair ();

        //PublicKey publicKey = kp.getPublic();
        //PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = readPublicKeyFromFileWithBouncy("public_key_2.pem");
        PrivateKey privateKey = readPrivateKeyFromFileWithBouncy("private_key_2.pem");
       // writePublicKeyToFile( publicKey,"public_key_2.pem");
       // writePrivateKeyToFile( privateKey,"private_key_2.pem");

        System.out.println("Public key: " + publicKey);
        System.out.println("Private key: " + privateKey);
        // Cripta il file di input usando la chiave pubblica
        encryptFile("input.txt", "encrypted3.txt", publicKey);

        // Decripta il file cifrato usando la chiave privata
        decryptFile("encrypted3.txt", "decrypted3txt", privateKey);
    }

    public static KeyPair creaKeyPair () throws Exception{
        KeyPairGenerator kpg = createKeyPairGenerator ();
        KeyPair keyPair = kpg.genKeyPair();
        return keyPair;
    }
    public static KeyPairGenerator createKeyPairGenerator () throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3200);
        return kpg;
    }
    public static void writePublicKeyToFile (PublicKey publicKey, String fileName) throws Exception{
        FileWriter publicKeyFileWriter = new FileWriter(fileName);
        publicKeyFileWriter.write("-----BEGIN PUBLIC KEY-----\n");
        publicKeyFileWriter.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        publicKeyFileWriter.write("\n-----END PUBLIC KEY-----");
        publicKeyFileWriter.close();
    }
    public static void writePrivateKeyToFile (PrivateKey privateKey, String fileName) throws Exception{
    FileWriter privateKeyFileWriter = new FileWriter(fileName);
        privateKeyFileWriter.write("-----BEGIN PRIVATE KEY-----\n");
        privateKeyFileWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        privateKeyFileWriter.write("\n-----END PRIVATE KEY-----");
        privateKeyFileWriter.close();
    }

    public static PublicKey readPublicKeyFromFileWithBouncy(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // leggi il file PEM in una stringa
        BufferedReader br = new BufferedReader(new FileReader(filePath));
        PemReader pr = new PemReader(br);
        PemObject pem = pr.readPemObject();
        byte[] content = pem.getContent();
        pr.close();

        // converti il contenuto PEM in un oggetto PublicKey
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return publicKey;
    }

    public static PrivateKey readPrivateKeyFromFileWithBouncy(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        BufferedReader br = new BufferedReader(new FileReader(filePath));
        PemReader pr = new PemReader(br);
        PemObject pem = pr.readPemObject();
        byte[] content = pem.getContent();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }

    public static PublicKey readPublicKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = readBytesFromFile(filePath);
        keyBytes =Base64.getDecoder().decode(keyBytes);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey readPrivateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[]  keyBytes= readBytesFromFile(filePath);
        keyBytes =Base64.getDecoder().decode(keyBytes);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static byte[] readBytesFromFile(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] buffer = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(buffer);
        }
        return buffer;
    }

    public static void encryptFile(String inputFilePath, String outputFilePath, PublicKey publicKey) throws Exception {

        // Legge il contenuto del file di input in un array di byte
        FileInputStream in = new FileInputStream(inputFilePath);
        byte[] inputBytes = new byte[(int) new File(inputFilePath).length()];
        in.read(inputBytes);
        in.close();

        // Crea un oggetto Cipher per cifrare i dati
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Cifra i dati del file di input e li scrive sul file di output
        byte[] outputBytes = cipher.doFinal(inputBytes);
        FileOutputStream out = new FileOutputStream(outputFilePath);
        out.write(outputBytes);
        out.close();
    }

    public static void decryptFile(String inputFilePath, String outputFilePath, PrivateKey privateKey) throws Exception {

        // Legge il contenuto del file cifrato in un array di byte
        FileInputStream in = new FileInputStream(inputFilePath);
        byte[] inputBytes = new byte[(int) new File(inputFilePath).length()];
        in.read(inputBytes);
        in.close();

        // Crea un oggetto Cipher per decifrare i dati
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decifra i dati del file cifrato e li scrive sul file di output
        byte[] outputBytes = cipher.doFinal(inputBytes);
        FileOutputStream out = new FileOutputStream(outputFilePath);
        out.write(outputBytes);
        out.close();
    }
}
