using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    readonly static string textFilePath = "file.txt";
    readonly static string encryptedFilePath = "encrypt.txt";
    readonly static string privateKeyFilePath = "privateKey.pem";
    readonly static string publicKeyFilePath = "publicKey.pem";

    static void Main()
    {
        Encrypt();
        Decrypt();       
    }
    static void Encrypt()
    {
        // генерация открытого и закрытого ключей RSA
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            // сохранение закрытого ключа в файл
            string privateKey = rsa.ToXmlString(true);
            File.WriteAllText(privateKeyFilePath, privateKey);
            string publicKey = rsa.ToXmlString(false);
            File.WriteAllText(publicKeyFilePath, publicKey);
        }

        // чтение текстового файла
        string text = File.ReadAllText(textFilePath);

        // генерация симметричного ключа и IV для AES
        byte[] key, iv;
        using (Aes aes = Aes.Create())
        {
            key = aes.Key;
            iv = aes.IV;

            // Шифрование данных симметричным алгоритмом AES
            byte[] encryptedData;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(text);
                }
                encryptedData = ms.ToArray();
            }

            // Шифрование симметричного ключа и IV с помощью открытого ключа RSA
            byte[] encryptedKey = EncryptData(key, privateKeyFilePath);
            byte[] encryptedIV = EncryptData(iv, privateKeyFilePath);

            // Генерация электронной подписи данных с использованием закрытого ключа RSA
            byte[] signature;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                string privateKey = File.ReadAllText(privateKeyFilePath);
                rsa.FromXmlString(privateKey);
                signature = rsa.SignData(encryptedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            // Запись зашифрованных данных и ключей в файл
            using (BinaryWriter writer = new BinaryWriter(File.Open(encryptedFilePath, FileMode.Create)))
            {
                writer.Write(encryptedKey.Length);
                writer.Write(encryptedKey);
                writer.Write(encryptedIV.Length);
                writer.Write(encryptedIV);
                writer.Write(encryptedData.Length);
                writer.Write(encryptedData);
                writer.Write(signature.Length);
                writer.Write(signature);
            }

            Console.WriteLine("Encrypt:\n Файл зашифрован и данные сохранены в файле " + encryptedFilePath);
        }

        static byte[] EncryptData(byte[] data, string publicKeyFilePath)
        {
            string publicKey = File.ReadAllText(publicKeyFilePath);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);
                return rsa.Encrypt(data, false);
            }
        }
    }
    static void Decrypt()
    {
        Console.WriteLine("Decrypt:");
        byte[] encryptedKey, encryptedIV, encryptedData, signature;

        // Чтение зашифрованных данных из файла
        using (BinaryReader reader = new BinaryReader(File.Open(encryptedFilePath, FileMode.Open)))
        {
            int encryptedKeyLength = reader.ReadInt32();
            encryptedKey = reader.ReadBytes(encryptedKeyLength);

            int encryptedIVLength = reader.ReadInt32();
            encryptedIV = reader.ReadBytes(encryptedIVLength);

            int encryptedDataLength = reader.ReadInt32();
            encryptedData = reader.ReadBytes(encryptedDataLength);

            int signatureLength = reader.ReadInt32();
            signature = reader.ReadBytes(signatureLength);
        }

        // Проверка цифровой подписи
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            string publicKey = File.ReadAllText(publicKeyFilePath);
            rsa.FromXmlString(publicKey);

            bool verified = rsa.VerifyData(encryptedData, SHA256.Create(), signature);

            Console.WriteLine(verified ? "Подпись верна." : "Подпись не совпадает!");

        }

        // Расшифровка симметричного ключа и IV с помощью закрытого ключа RSA
        byte[] key = DecryptData(encryptedKey, privateKeyFilePath);
        byte[] iv = DecryptData(encryptedIV, privateKeyFilePath);

        // Расшифровка данных симметричным алгоритмом AES
        string decryptedText;
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream(encryptedData))
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                decryptedText = sr.ReadToEnd();
            }
        }

        Console.WriteLine("Расшифрованное сообщение: " + decryptedText);
    }

    static byte[] DecryptData(byte[] data, string privateKeyFilePath)
    {
        string privateKey = File.ReadAllText(privateKeyFilePath);
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(privateKey);
            return rsa.Decrypt(data, false);
        }
    }
}
