using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Linq;

class DecryptMessageFromRails
{
    static void Main(string[] args)
    {
        string example_token = "MVBBZFdsRklIU1dOd08zaVdaWG8ydz09LS14R2JsTjdLbEJWWjBLeG5ybVhJaWRRPT0=--3b2dc243d69713dc60176c033ffba71fd353781e";
        string example_secret = "3cd327ee31b70a184f56ef4e43ca4e9a";
        
        string decryptedToken =  ExtractCipherDataAndDecrypt(example_token, example_secret);
        
        Console.WriteLine("Decrypted String: {0}", decryptedToken);
    }
    
    public static string ExtractCipherDataAndDecrypt(string encryptedDataFromRails, string key) {
        // First split the encrypted data, format is "{EncryptedTokenEncodedToBase64}--{SHA1Digest}"
        string[] dataArray = encryptedDataFromRails.Split("--");
        
        // ensure no padding attack
        EnsureNoPaddingAttackOccured(dataArray[0], dataArray[1], key);
        
        // next decode the base64 encrypted token and convert to string
        // format will be: "{Base64EncryptedToken}--{Base64IV}"
        byte[] encryptedBase64TokenBytes = Convert.FromBase64String(dataArray[0]);
        string encryptedBase64Token = System.Text.ASCIIEncoding.ASCII.GetString(encryptedBase64TokenBytes);
        Console.WriteLine("Encrypted Token: {0}", encryptedBase64Token);
        
        // split again to get token and IV separately and pass on to decryption
        string[] tokenData =  encryptedBase64Token.Split("--");
        
        return Decrypt(tokenData[0], key, tokenData[1]);
    }
    
    // SHA1 digest is used to make sure no padding attack(https://en.wikipedia.org/wiki/Padding_oracle_attack) has happened
    // If the value generated doesnt match then the attack has occured
    // Raise exception in such a case
    public static void EnsureNoPaddingAttackOccured(string encryptedData, string digest, string key) {
        HMACSHA1 hmac = new HMACSHA1(Encoding.ASCII.GetBytes(key));
        hmac.Initialize();
        byte[] buffer = Encoding.ASCII.GetBytes(encryptedData);
        string generatedDigest = BitConverter.ToString(hmac.ComputeHash(buffer)).Replace("-", "").ToLower();
        if(generatedDigest == digest) {
            Console.WriteLine("Digest matches, no padding attack occured, proceeding with decryption");
        } else {
            // throw appropriate exception - which is ??
            throw new Exception("WE ARE UNDER ATTACK");
        }
    }
    
    
    
    public static void EncryptUsingCBC(string toEncryptString, byte[] key, byte[] iv) {
        byte[] toEncrypt = System.Text.Encoding.UTF8.GetBytes(toEncryptString);

        byte[] encrypted = null;

        //encrypt
        using (var aes = new AesCryptoServiceProvider())
        {
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.IV = iv;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(toEncryptString);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
        }
        Console.WriteLine("Encrypted String: {0}", Convert.ToBase64String(encrypted));
    }
    
    public static string DecryptUsingCBC(byte[] toDecrypt, byte[] AesIV, byte[] AesKey) {
        byte[] src = toDecrypt;
        byte[] dest = new byte[src.Length];
        
        using (var aes = new AesCryptoServiceProvider())
        {
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.IV = AesIV;
            aes.Key = AesKey;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            
            // decryption
            using (ICryptoTransform decrypt = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] decryptedText = decrypt.TransformFinalBlock(src, 0, src.Length);

                return Encoding.UTF8.GetString(decryptedText);
            }
        }
    }
    
    
    public static string Decrypt(string cipherData, string keyString, string ivString) {
        byte[] key = Encoding.UTF8.GetBytes(keyString);
            Console.WriteLine("Key Length: {0}", key.Length);
        
        byte[] iv  = System.Convert.FromBase64String(ivString);
            Console.WriteLine("IV Length: {0}", iv.Length);
        
        byte[] cip = Convert.FromBase64String(cipherData);
            Console.WriteLine("Cipher Data Length: {0}", cip.Length);
        
        try
        {
            EncryptUsingCBC("Fake Token", key, iv);    
            return DecryptUsingCBC(cip, iv, key);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
            return null;
        }
        // You may want to catch more exceptions here...
    }
}
