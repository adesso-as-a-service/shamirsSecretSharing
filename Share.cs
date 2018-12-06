using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;

namespace shamirsSecretSharing
{
    public class Share
    {

        /// <summary>
        /// X-value of the share
        /// </summary>
        private byte[] X
        {
            get;
            set;
        }

        /// <summary>
        /// Y-value of the share
        /// </summary>
        private byte[] Y
        {
            get;
            set;
        }

        /// <summary>
        /// Create a share
        /// </summary>
        public Share(byte[] x, byte[] y)
        {
            Array.Copy(y, Y, y.Length);
            Array.Copy(x, X, x.Length);
        }

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
    }
}
