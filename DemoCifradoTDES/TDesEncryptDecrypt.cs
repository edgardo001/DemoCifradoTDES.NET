using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DemoCifradoTDES
{
    class TDesEncryptDecrypt
    {
        // AesCryptoServiceProvider
        private TripleDESCryptoServiceProvider myTDes = new TripleDESCryptoServiceProvider();
        /// <summary>
        /// Vector de Inicializacion: No se puede encriptar sin él. Es de 8 bytes de longitud para el algoritmo de Rijndael. No es una 2ª llave, por lo tanto, no se trata de una dato que haya que esconder, únicamente hay que considerar que hay que usar el mismo IV para encriptar/desencriptar un mensaje concreto. Un error común es utilizar el mismo vector de inicialización en todas las encriptaciones. Utilizar siempre un mismo IV es equivalente en seguridad a no utilizar encriptación.
        /// </summary>
        private const string TDesIV = "!QAZ2WSX";//8
        /// <summary>
        /// Llave de encriptacion: Esta es la principal información para encriptar/desencriptar en los algoritmos simétricos. Toda la seguridad de un sistema simétrico depende de dónde esté esta llave, cómo esté compuesta y quién tiene acceso. Éste es un dato que debe conocerse única y exclusivamente por los interlocutores de la comunicación. De otra forma, la seguridad en la comunicación se vería comprometida.
        /// </summary>
        private const string TDesKey = "5TGB&YHN7UJM(IK<5TGB&YHN";//24
        /// <summary>
        /// Constructor default
        /// </summary>
        /// <param name="BlockSize"></param>
        /// <param name="KeySize"></param>
        /// <param name="cipherMode">Cipher Block Chaining Mode: Es una extensión de ECB que añade cierta seguridad (usa un vector de inicialización IV). Es el modo de cifrado por bloques más usado.</param>
        /// <param name="paddingMode">La cadena de relleno PKCS #7 consta de una secuencia de bytes, en la que cada byte es igual al número total de bytes de relleno agregados.</param>
        public TDesEncryptDecrypt(int BlockSize = 64, int KeySize = 192, string IV = TDesIV, string Key = TDesKey, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            myTDes.BlockSize = BlockSize;
            myTDes.KeySize = KeySize;
            myTDes.IV = Encoding.UTF8.GetBytes(IV);
            myTDes.Key = Encoding.UTF8.GetBytes(Key);
            myTDes.Mode = cipherMode;
            myTDes.Padding = paddingMode;
        }
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="myTDes"></param>
        public TDesEncryptDecrypt(TripleDESCryptoServiceProvider myTDes)
        {
            this.myTDes = myTDes;
        }
        /// <summary>
        /// AES encryption
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public byte[] Encrypt256(byte[] src)
        {
            try
            {
                // encryption
                using (ICryptoTransform encrypt = myTDes.CreateEncryptor())
                {
                    return encrypt.TransformFinalBlock(src, 0, src.Length);
                }
            }
            catch (Exception)
            {

                throw;
            }
        }
        /// <summary>
        /// AES decryption
        /// </summary>
        public byte[] Decrypt256(byte[] src)
        {
            try
            {
                // decryption
                using (ICryptoTransform decrypt = myTDes.CreateDecryptor())
                {
                    return decrypt.TransformFinalBlock(src, 0, src.Length);
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public static string byteArrayToB64(byte[] src)
        {
            try
            {
                return Convert.ToBase64String(src);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="src"></param>
        /// <returns></returns>
        public static byte[] B64ToByteArray(string src)
        {
            try
            {
                return System.Convert.FromBase64String(src);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
    }
}
