using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace shamirsSecretSharing
{
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
        /// Prime modulo used in little endian format
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

        private uint[] allowedSizes = { 1024, 2048, 3072, 4096 };

        public PublicKey(uint n, uint m, uint size)
        {
            // Validate Arguments
            if (m < n) throw new ArgumentException("m has to be greater or equal to n");
            if (n < 2) throw new ArgumentException("n has to be greater or equal to 2");
            if (!Array.Exists(allowedSizes, element => element == size)) throw new ArgumentException(string.Format("size has to be in ( {0} )", string.Join(", ", allowedSizes)));

            N = n;
            M = m;
            ModSize = size;

        }
    }
}
