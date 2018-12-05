using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;


namespace shamirsSecretSharing
{
    public class SssEngine
    {
        private PublicKey PublicKey
        {
            get;
            set;
        }
        

        public SssEngine(uint n, uint m, uint size)
        {
            PublicKey = new PublicKey(n, m, size);
        }

        public Tuple<PublicKey,Share[]> Encrypt(byte [] secret)
        {
            return Encrypt(PublicKey, secret);
        }

        public static Tuple<PublicKey, Share[]> Encrypt(uint n, uint m, uint size, byte[] secret)
        {
            return Encrypt(new PublicKey(n, m, size), secret);
        }

        public static Tuple<PublicKey, Share[]> Encrypt(PublicKey pub, byte[] secret)
        {
            if (secret.Length > (pub.ModSize / 8) - 1) throw new ArgumentException("Secret exceeds the size of the prime modulo");
            
            rand.
            BigInteger prime = BigInteger.ProbablePrime(pub.ModSize, );
        }
    }
}
