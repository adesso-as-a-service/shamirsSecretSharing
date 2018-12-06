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

            Polynomial poly = new Polynomial(pub);
            poly.Init(secret);

            byte[][] xValues = new byte[pub.M][];
            byte[][] yValues;

            // just for testing, add custom points later
            for (int i = 0; i < xValues.Length; i++)
            {
                xValues[i] = BitConverter.GetBytes((uint)(i + 1));
            }

            yValues = poly.CalculatePoints(xValues);
            Share[] shares = new Share[yValues.Length];

            for (int i = 0; i < shares.Length; i++)
            {
                shares[i] = new Share(xValues[i], yValues[i]);

                for (int j = 0; j < yValues[i].Length; j++)
                {
                    yValues[i][j] = 0;
                }
            }

            pub.CalculateHashes(shares);

            return new Tuple<PublicKey, Share[]>(pub, shares);
        }

        public byte[] Decrypt(Share[] shares)
        {

        }
    }
}
