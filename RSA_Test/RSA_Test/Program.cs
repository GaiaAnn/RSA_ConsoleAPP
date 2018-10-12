using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA_Test
{
    class Program
    {
        static void Main(string[] args)
        {
            string testString = @"HELLO I'm GaiaAnn :-)";
            string encryptResult = string.Empty;
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            string signature = string.Empty;
            #region Sample Private/Public key in case you dont have .pem files
            string SamplePrivateKey = @"MIICWwIBAAKBgQDIA7KkMpZsdmyQbQmitRzkuGodxV+baXzDWX7K7idQJ8q0YDXsUtEWOrfeYm/PXjLLD7fKOVCUonvOM7xLUZL2rc2GWEMPv7X/szMnNKd8cwLHKILh
tk4KkuOkhGF+TJWOIvj4fSixrXavtQiyRrbJd/dVcSGKxEh5S8uzEqnPGQIDAQAB
AoGACf69T51DjRoB5Nm+EIZyci+RBfnWBEMqO+zd/DAYgNXsOEVSjIO69RxsEc3j
fn5blXAspAtnLnZML4rATxc9e8WoATAe4s3it2Dp/IEk0FOte8/5jAoSBKi2oLif
A6vN0JG9sZl0V1meVKgeUrZDgrCJxTcjpZ/lruADEzW+Ik0CQQDjCAyQuCDXAKc+
IDLrfQii9xqPo9vmibfosbhELVSsA/KUKRpEjEFx0Qtb3YwBk3ibdeTtL4Co1P7j
grYHWahjAkEA4YkkaQgqBZb+59/MuP/QZzy5sYtNwYkrwheL2asIf4s/MrWnufvR
jiOgj6c3G8UMieyghIDe6n5wgP11+/cdUwJAW93K79iB+V4bTolK8X1DvGXPCqac
ednqYC9hx7ysEXr7crZ7GZfDd6HGPeMVHyIkYIvBGbTqE+c0SK2AqNK/zwJAf3wa
9bfksPYyLnWl7ijD76c2u/InSK+16WeP6MEx846NcaeXIJ0EThk7aBg4IV1YAhqc
fWmvF9PS2kbrSzra+wJALM2HQN8Iltta6bVFaJamAOHWbVkBDllqA8kHEieJfoX7
3DepJLJm8Fg2/reTWPIoKmMA4E0BEVwlCQdfvFBeWQ==";
            string SamplePublicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIA7KkMpZsdmyQbQmitRzkuGod
xV+baXzDWX7K7idQJ8q0YDXsUtEWOrfeYm/PXjLLD7fKOVCUonvOM7xLUZL2rc2G
WEMPv7X/szMnNKd8cwLHKILhtk4KkuOkhGF+TJWOIvj4fSixrXavtQiyRrbJd/dV
cSGKxEh5S8uzEqnPGQIDAQAB";
            #endregion


            try
            {
                //read publicKey from .pem file and escape header & footer
                using (var reader = File.OpenText(@"C:\Program Files\OpenSSL-Win64\bin\1024publicKey.pem"))
                {
                    publicKey = GetKeyContentFromPEM(reader.ReadToEnd(), "RsaPublicKey");
                };

                //read privateKey from .pem file and escape header & footer
                using (var reader = File.OpenText(@"C:\Program Files\OpenSSL-Win64\bin\1024privateKey.pem"))
                {
                    privateKey = GetKeyContentFromPEM(reader.ReadToEnd(), "RsaPrivateKey");
                };
            }
            catch
            {
                //if error I'll replace to sample Key so that you can check function work or not
                privateKey = SamplePrivateKey;
                publicKey = SamplePublicKey;
            }

            Console.WriteLine($"Test String is : {testString}");
            Console.WriteLine("");



            #region Encrypt
            try
            {
                Console.WriteLine("-----------------[Start using PublicKey to Encrypt Content]---------------------------");
                encryptResult = Encrypt(publicKey, testString);
                Console.WriteLine(encryptResult);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encrypt Error Occur:");
                Console.WriteLine(ex.ToString());
            }
            Console.WriteLine($"-----------------End Encrypt Content ---------------------------");
            #endregion

            Console.WriteLine("");

            #region Decrypt
            try
            {
                Console.WriteLine("-----------------[Start using PrivateKey to Decrypt Content]---------------------------");
                string desContent = Decrypt(privateKey, encryptResult);
                Console.WriteLine(desContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Occur:");
                Console.WriteLine(ex.ToString());
            }
            Console.WriteLine($"-----------------End Decode Content ---------------------------");
            #endregion

            Console.WriteLine("");

            #region Sign
            try
            {
                Console.WriteLine("-----------------[Start using PrivateKey to Sign]---------------------------");
                signature = Sign(testString, privateKey, "utf-8");
                Console.WriteLine(signature);
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Sign Error Occur:");
                Console.WriteLine(ex.ToString());
            }
            Console.WriteLine("-----------------End Encode Content-----------------------------");
            #endregion

            Console.WriteLine("");

            #region Verify Sign
            try
            {
                Console.WriteLine("-----------------[Start using PublicKey to verify sign]---------------------------");
                bool IsVerify = VerifySign(testString, signature, publicKey, "utf-8");
                Console.WriteLine($"-----------------Verify Result : [{IsVerify.ToString()}]---------------------------");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Verify Sign Error :");
                Console.WriteLine(ex.ToString());
            }
         
            Console.WriteLine("----------------- End Verify ------------------------------");
            #endregion

            Console.ReadLine();

        }

        /// <summary>
        /// remove header & footer format string
        /// </summary>
        /// <param name="pemString"></param>
        /// <param name="type">Certificate/RsaPrivateKey/RsaPublicKey</param>
        /// <returns></returns>
        public static string GetKeyContentFromPEM(string pemString, string type)
        {
            string header; string footer;

            switch (type)
            {
                case "Certificate":
                    header = "-----BEGIN CERTIFICATE-----";
                    footer = "-----END CERTIFICATE-----";
                    break;
                case "RsaPrivateKey":
                    header = "-----BEGIN RSA PRIVATE KEY-----";
                    footer = "-----END RSA PRIVATE KEY-----";
                    break;
                case "RsaPublicKey":
                    header = "-----BEGIN PUBLIC KEY-----";
                    footer = "-----END PUBLIC KEY-----";
                    break;
                default:
                    return null;
            }

            int start = pemString.IndexOf(header) + header.Length;
            int end = pemString.IndexOf(footer, start) - start;
            return pemString.Substring(start, end);
        }
        private static string Encrypt(string publicKey, string content)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //Get publicKey information
            RSAParameters parameters = ConvertFromPublicKey(publicKey);
            rsa.ImportParameters(parameters);
            //Convert to UTF8 bytes
            var content_utf = rsa.Encrypt(Encoding.UTF8.GetBytes(content), false);
            //Convert to Base64String
            var encryptString = Convert.ToBase64String(content_utf);

            return encryptString;
        }
        private static string Decrypt(string privateKey,string encryptContent)
        {
            //Get privateKey information
            RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(Convert.FromBase64String(privateKey));
            //Convert Base64String Into byte then do Decrypt
            var desContent = rsa.Decrypt(Convert.FromBase64String(encryptContent), false);
            //return UTF string result
            return Encoding.UTF8.GetString(desContent);
        }
        public static string Sign(string content, string pvKey, string input_charset)
        {
            byte[] Data = Encoding.GetEncoding(input_charset).GetBytes(content);
            byte[] privatekey;
            privatekey = Convert.FromBase64String(pvKey);
            RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(privatekey);
            SHA1 sh = new SHA1CryptoServiceProvider();
            byte[] signData = rsa.SignData(Data, sh);
            
            return Convert.ToBase64String(signData);
        }
        private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();	//advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();	//advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)	//version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }
            finally { binr.Close(); }
        }
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            }



            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }
        public static bool VerifySign(string content, string signedString, string publicKey, string input_charset)
        {
            signedString = signedString.Replace("*", "+");
            signedString = signedString.Replace("-", "/");
            return JiJianverify(content, signedString, publicKey, input_charset);
        }
        /// <summary>
        /// verify sign
        /// </summary>
        /// <param name="content"></param>
        /// <param name="signedString"></param>
        /// <param name="publicKey"></param>
        /// <param name="input_charset"></param>
        public static bool JiJianverify(string content, string signedString, string publicKey, string input_charset)
        {
            bool result = false;
            byte[] Data = Encoding.GetEncoding(input_charset).GetBytes(content);

            byte[] data = Convert.FromBase64String(signedString);
            RSAParameters paraPub = ConvertFromPublicKey(publicKey);
            RSACryptoServiceProvider rsaPub = new RSACryptoServiceProvider();
            rsaPub.ImportParameters(paraPub);
            SHA1 sh = new SHA1CryptoServiceProvider();
            result = rsaPub.VerifyData(Data, sh, data);
            return result;
        }
        private static RSAParameters ConvertFromPublicKey(string publicKey)
        {

            byte[] keyData = Convert.FromBase64String(publicKey);
            if (keyData.Length < 162)
            {
                throw new ArgumentException("[PublicKey] .pem file content is incorrect.");
            }
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(keyData);
            RSAParameters para = new RSAParameters();
            para.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            para.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            return para;
        }
      
    }
}
