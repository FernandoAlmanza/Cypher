using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ProxyValueCypher
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptController : ControllerBase
    {
        // POST: api/Encrypt
        [HttpPost]
        public Object Post(JsonObject request)
        {
            byte[] password = Encoding.ASCII.GetBytes(request["settings"]["password"].ToString());
            byte[] salt = Encoding.ASCII.GetBytes(request["settings"]["salt"].ToString());
            string value = request["value"].ToString();
            
            string output = EncodeToUrlSafeBase64(EncryptStringToBytes_Aes(value, password, salt));
            
            return Ok(new
            {
                Message = "Success!",
                Details = new {
                    EncriptedValue =  output,
                    AlgorithmUsed = request["settings"]["algorithm"],
                    SaltParsed =  Encoding.UTF8.GetString(salt),
                    UtilURI = $"https://imagenmlm.starmedica.com:8443/launch?&AccessionNumber=-24-24-24{output}-3D&action=view" +
                              $"accession&encid=default&username=authtoken&password=bW9iaWxpdHl1cmw6MzgyNTc3MzI2O" +
                              $"To2NjQ1NWRhMzkyZGI5MzQ4MDdkOTE5MzU3NjUzM2IzNA%3D%3D"
                }
            });
            
        }
        
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] salt)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(key, salt, 1);
                aesAlg.Key = keyGenerator.GetBytes(aesAlg.KeySize / 8);

                aesAlg.GenerateIV();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            
            return encrypted;
        }

        static string EncodeToUrlSafeBase64(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_').Replace("EAAAA", "");
        }

        
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] salt)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(key, salt, 5);
                aesAlg.Key = keyGenerator.GetBytes(aesAlg.KeySize / 8);

                byte[] iv = new byte[sizeof(int)];
                Array.Copy(cipherText, iv, iv.Length);
                aesAlg.IV = iv;

                int bytesRead = iv.Length;
                using (MemoryStream msDecrypt = new MemoryStream(cipherText, bytesRead, cipherText.Length - bytesRead))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
