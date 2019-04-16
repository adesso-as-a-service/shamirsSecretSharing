using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;

namespace shamirsSecretSharing
{
    public class Share
    {

        /// <summary>
        /// X-value of the share
        /// </summary>
        public byte[] X
        {
            get;
            internal set;
        }

        /// <summary>
        /// Y-value of the share
        /// </summary>
        public byte[] Y
        {
            get;
            internal set;
        }

        /// <summary>
        /// Create a share
        /// </summary>
        public Share(byte[] x, byte[] y)
        {
            Y = new byte[y.Length];
            X = new byte[x.Length];
            Array.Copy(y, Y, y.Length);
            Array.Copy(x, X, x.Length);
        }


        /// <summary>
        /// Calculate the SHA256-Hash of the share
        /// </summary>
        public byte[] GetHash()
        {
            Sha256Digest sha256 = new Sha256Digest();
            byte[] hash = new byte[sha256.GetByteLength()];
            sha256.BlockUpdate(X, 0, X.Length);
            sha256.BlockUpdate(Y, 0, Y.Length);
            sha256.GetByteLength();
            sha256.DoFinal(hash, 0);
            return hash;
        }

        public override bool Equals(object obj)
        {
            var share = obj as Share;
            return this.GetHash().SequenceEqual(share.GetHash());
        }

        public byte[] ToBinary()
        {
            List<byte> retVal = new List<byte> { };
            byte[] help, len;

            // add X
            retVal.Add(0x01);
            help = PublicKey.getSubarry(X, 0, X.Length);
            len = BitConverter.GetBytes(help.Length);
            retVal.AddRange(len);
            retVal.AddRange(help);

            // add encryptedKey

            retVal.Add(0x02);
            help = PublicKey.getSubarry(Y, 0, Y.Length);
            len = BitConverter.GetBytes(help.Length);
            retVal.AddRange(len);
            retVal.AddRange(help);

            return retVal.ToArray();
        }

        public static Share FromBinary(byte[] array)
        {
            Share sh;
            byte[] x, y;
            int len;
            x = y = new byte[0];
            for (int i = 0; i < array.Length; i++)
            {
                switch (array[i])
                {
                    case 0x01:
                        len = BitConverter.ToInt32(array, i + 1);
                        i = i + 4;
                        x = PublicKey.getSubarry(array, i + 1, i + 1 + len);
                        i = i + len;
                        break;
                    case 0x02:
                        len = BitConverter.ToInt32(array, i + 1);
                        i = i + 4;
                        y = PublicKey.getSubarry(array, i + 1, i + 1 + len);
                        i = i + len;
                        break;
                    default:
                        throw new FormatException("Share Format is incorrect");
                }
            }

            sh = new Share(x,y);
            return sh;
        }
    }
    
}
