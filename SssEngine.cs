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

        public SssEngine(PublicKey pub)
        {
            PublicKey = pub;
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
            if (secret.Length + 1 > (pub.ModSize / 8) - 1) throw new ArgumentException("Secret exceeds the size of the prime modulo");

            // Added a padding of 0x1 to allow for zeros in the beginning.
            byte[] paddedSecret = new byte[secret.Length + 1];
            paddedSecret[0] = 0x1;
            Array.Copy(secret, 0, paddedSecret, 1, secret.Length);

            Polynomial poly = new Polynomial(pub);
            poly.Init(paddedSecret);


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

            for (int i = 0; i < secret.Length; i++)
            {
                paddedSecret[i + 1] = 0;
            }

            pub.CalculateHashes(shares);

            return new Tuple<PublicKey, Share[]>(pub, shares);
        }

        public byte[] Decrypt(Share[] shares)
        {
            return Decrypt(PublicKey, shares);
        }

        public static byte[] Decrypt(PublicKey pub, Share[] shares)
        {
            if (shares.Length < pub.N) throw new ArgumentException(string.Format("Not enough shares. Needed: {0} Provided: {1}", pub.N, shares.Length));
            if (shares.Distinct().Count() != shares.Count()) throw new ArgumentException("The provided shares contain duplicates");
            for (int i = 0; i < pub.N; i++)
            {
                if (!pub.ContainsShare(shares[i])) throw new ArgumentException(string.Format("The share #{0} doesn't belong to this public key", i));
            }

            byte[][] xValues, yValues;

            xValues = new byte[pub.N][];
            yValues = new byte[pub.N][];
            for (int i = 0; i < pub.N; i++)
            {
                xValues[i] = shares[i].X;
                yValues[i] = shares[i].Y;
            }
            byte[] paddedSecret, secret;
                
            paddedSecret = Polynomial.Reconstruct(xValues, yValues, new byte[0], pub.PrimeModulo);

            if (paddedSecret[0] != 0x1) throw new FormatException("Returned secret has an incorrect padding");

            secret = new byte[paddedSecret.Length - 1];
            Array.Copy(paddedSecret, 1, secret, 0, paddedSecret.Length - 1);
            for (int i = 0; i < paddedSecret.Length; i++)
            {
                paddedSecret[i] = 0;
            }
            return secret;
        }

    }
}
