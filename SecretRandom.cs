using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Math;

namespace shamirsSecretSharing
{
    class SecretRandom : Random
    {
        private RNGCryptoServiceProvider Rng {
            get;
            set;
        }


        public SecretRandom()
        {
            Rng = new RNGCryptoServiceProvider();

        }

        override public int Next()
        {
            byte [] random = new byte[4];
            Rng.GetBytes(random);
            random[3] = (byte)(random[3] & 0x7f);
            return Math.Abs(BitConverter.ToInt32(random, 0));
        }

        override public int Next(int maxValue)
        {
            int bits = (int)Math.Ceiling(Math.Log(maxValue, 2));
            int mask = (1 << (bits - 1)) - 1;
            int candidate;

            do
            {
                candidate = Next() & mask;
            } while (candidate > maxValue);

            return candidate;
        }

        override public int Next(int minValue, int maxValue)
        {
            return Next(maxValue - minValue) + minValue;
        }

        public override void NextBytes(byte[] buffer)
        {
            Rng.GetBytes(buffer);
        }

        public override double NextDouble()
        {
            /* This is a totally random double, but it is not uniform
            byte[] buffer = new byte[8];
            byte[] exp = BitConverter.GetBytes(Next(1023));
            NextBytes(buffer);

            buffer[7] = (byte)((exp[1] << 4) + (exp[0] >> 4));
            buffer[6] = (byte)((buffer[6] & 0xf) | (exp[0] << 4));

            return BitConverter.ToDouble(buffer, 0);
            */
            byte[] buffer = new byte[8];
            UInt64 val;
            do
            {
                NextBytes(buffer);
                val = BitConverter.ToUInt64(buffer, 0);
            } while (val/UInt64.MaxValue == 1);

            return (double)val / UInt64.MaxValue;
        }
    }
}
