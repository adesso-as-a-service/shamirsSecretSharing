using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;

namespace shamirsSecretSharing
{
    /// <summary>
    /// Public Key for shamirs secret sharing
    /// </summary>
    public class PublicKey
    {
        /// <summary>
        /// Number of shares needed to recover the stored secret
        /// </summary>
        public uint N
        {
            get;
            internal set;
        }

        /// <summary>
        /// Number of shares to be created
        /// </summary>
        public uint M
        {
            get;
            internal set;
        }

        /// <summary>
        /// Size in bits of the chosen prime number
        /// </summary>
        public uint ModSize
        {
            get;
            internal set;
        }

        /// <summary>
        /// Prime modulo used in little endian format and unsigned
        /// </summary>
        public byte[] PrimeModulo
        {
            get;
            internal set;
        }

        /// <summary>
        /// Hashs of the private shares 
        /// </summary>
        private byte[][] PrivateShareHashs 
        {
            get;
            set;
        }

        public static readonly uint[] allowedSizes = { 1024, 2048, 3072, 4096 };


        private PublicKey(uint n, uint m, uint ModSize ,byte[] primeModulo)
        {
            if (m < n) throw new ArgumentException("m has to be greater or equal to n");
            if (n < 2) throw new ArgumentException("n has to be greater or equal to 2");
            if (!Array.Exists(allowedSizes, element => element == ModSize)) throw new ArgumentException(string.Format("size has to be in ( {0} )", string.Join(", ", allowedSizes)));

            this.N = n;
            this.M = m;
            this.ModSize = ModSize;
            this.PrimeModulo = primeModulo;
        }
        /// <summary>
        /// Creates a public key with the given parameters
        /// </summary>
        /// <param name="n"> Number of shares needed to decrypt the secret</param>
        /// <param name="m"> Number of shares to be created</param>
        /// <param name="size"> BitSize of the prime modulo</param> 
        public PublicKey(uint n, uint m, uint size)
        {
            // Validate Arguments
            if (m < n) throw new ArgumentException("m has to be greater or equal to n");
            if (n < 2) throw new ArgumentException("n has to be greater or equal to 2");
            if (!Array.Exists(allowedSizes, element => element == size)) throw new ArgumentException(string.Format("size has to be in ( {0} )", string.Join(", ", allowedSizes)));

            this.N = n;
            this.M = m;
            this.ModSize = size;

            Random rand = new SecureRandom();
            BigInteger prime = BigInteger.ProbablePrime((int)this.ModSize, rand);
            this.PrimeModulo = prime.ToByteArrayUnsigned();
        }


        /// <summary>
        /// Calculates and stores the hashes of the given shares to be associated with this public key
        /// </summary>
        /// <param name="shares"> Shares to be associated with this public key</param>
        public void CalculateHashes(Share[] shares)
        {
            Sha256Digest sha256Digest = new Sha256Digest();
            this.PrivateShareHashs = new byte[shares.Length][];

            for (int i = 0; i < shares.Length; i++)
            {
                this.PrivateShareHashs[i] = shares[i].GetHash();
            }
        }

        /// <summary>
        /// Checks if the given share is associated with this share
        /// </summary>
        /// <param name="share"> Shares to be checked</param>
        public bool ContainsShare(Share share)
        {
            return Array.Exists(this.PrivateShareHashs, element => element.SequenceEqual(share.GetHash()));
        }

        public byte[] ToBinary()
        {
            List<byte> retVal = new List<byte> { };
            byte[] helper;
            byte[] len;

            // append type 0x01 = N
            retVal.Add(0x01);

            // getByteArray
            helper = BitConverter.GetBytes(N);

            // append length and helper
            retVal.AddRange(helper);



            // append type 0x02 = M
            retVal.Add(0x02);

            // getByteArray
            helper = BitConverter.GetBytes(M);

            // append length and helper
            retVal.AddRange(helper);


            // append type 0x03 = ModSize
            retVal.Add(0x03);

            // getByteArray
            helper = BitConverter.GetBytes(ModSize);

            // append length and helper
            retVal.AddRange(helper);


            // append type 0x04 = primeModulo
            retVal.Add(0x04);

            // getByteArray
            helper = PrimeModulo;
            len = BitConverter.GetBytes(helper.Length);

            // append length and helper
            retVal.AddRange(len);
            retVal.AddRange(helper);


            // append type 0x05 = Private Shares
            retVal.Add(0x05);

            // getByteArray
            helper = getBinaryPrivateShares();
            len = BitConverter.GetBytes(helper.Length);

            // append length and helper
            retVal.AddRange(len);
            retVal.AddRange(helper);

            return retVal.ToArray();
        }

        private byte[] getBinaryPrivateShares()
        {
            List<byte> retVal = new List<byte> { };
            byte[] helper;
            byte[] len;

            for (int x = 0; x < PrivateShareHashs.Length; x++)
            {
                // append type 0x01 = Private Share
                retVal.Add(0x01);

                // getByteArray
                helper = PrivateShareHashs[x];
                len = BitConverter.GetBytes(helper.Length);

                // append length and helper
                retVal.AddRange(len);
                retVal.AddRange(helper);
            }

            return retVal.ToArray();

        } 

        public static PublicKey ReadFromBinary(byte[] pubBin)
        {
            PublicKey pubKey;
            uint n, m, modSize;
            byte[] primeModulo;
            byte[][] privateKeyHashs;
            byte[] help;
            int len;
            n = m = modSize = 0;
            primeModulo = new byte[0];
            privateKeyHashs = new byte[0][];
            for (int i = 0; i < pubBin.Length; i++)
            {
                switch (pubBin[i]) {
                    case 0x01:
                        n = BitConverter.ToUInt32(pubBin, i + 1);
                        i = i + 4;
                        break;
                    case 0x02:
                        m = BitConverter.ToUInt32(pubBin, i + 1);
                        i = i + 4;
                        break;
                    case 0x03:
                        modSize = BitConverter.ToUInt32(pubBin, i + 1);
                        i = i + 4;
                        break;
                    case 0x04:
                        len = BitConverter.ToInt32(pubBin, i + 1);
                        i = i + 4;
                        primeModulo = getSubarry(pubBin, i + 1, i + 1 + len);
                        i = i + len;
                        break;
                    case 0x05:
                        len = BitConverter.ToInt32(pubBin, i + 1);
                        i = i + 4;
                        help = getSubarry(pubBin, i + 1, i + 1 + len);
                        privateKeyHashs = privateKeyHashsFromBinary(help);
                        i = i + len;
                        break;

                    default:
                        throw new FormatException("PublicKey Binary Format is incorrect");
                }
            }
            pubKey = new PublicKey(n, m, modSize,primeModulo);
            pubKey.PrivateShareHashs = privateKeyHashs;

            return pubKey;
        }

        private static byte[][] privateKeyHashsFromBinary(byte[] array)
        {
            List<byte[]> retVal = new List<byte[]> { };
            byte[] help;
            int len;
            for (int i = 0; i < array.Length; i++)
            {
                switch (array[i])
                {
                    case 0x01:
                        len = BitConverter.ToInt32(array, i + 1);
                        i = i + 4;
                        help = getSubarry(array, i + 1, i + 1 + len);
                        retVal.Add(help);
                        i = i + len;
                        break;
                    default:
                        throw new FormatException("PrivateKeyHash Binary Format is incorrect");
                }
            }
            return retVal.ToArray();
        }

        public static byte[] getSubarry(byte[] array, int start, int stop)
        {
            if (stop > array.Length) throw new ArgumentException("Stop is out of bounds");
            if (start < 0) throw new ArgumentException("Start is out of bounds");
            if (start >= stop) throw new ArgumentException("Start can't be bigger or as big as stop");

            byte[] retVal = new byte[stop - start];
            Array.Copy(array, start, retVal, 0, stop - start);
            return retVal;
        }
    }
}
