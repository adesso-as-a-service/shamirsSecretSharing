using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace shamirsSecretSharing
{
    /// <summary>
    /// Creates an class for polynomial Calculation on a finite group. 
    /// Only the zero coefficient can be set, the rest is calculated automatically
    /// </summary>
    class Polynomial
    {

        /// <summary>
        /// The prime modulo of the finite group
        /// </summary>
        private BigInteger PrimeModulo;

        /// <summary>
        /// The number of coefficients to be used (degree + 1)
        /// </summary>
        private uint NumCoefficients;

        /// <summary>
        /// Size of the modulo in bits
        /// </summary>
        private uint ModuloBitSize;

        /// <summary>
        /// Coefficients of the polynomial
        /// </summary>
        private BigInteger[] Coefficients;

        /// <summary>
        /// RNG
        /// </summary>
        private SecretRandom Rand;


        /// <summary>
        /// Create the base polynomial
        /// </summary>
        /// <param name="inPrimeModulo"> Prime number of the finite group</param>
        /// <param name="inNumCoefficients"> Number of coefficients of the polynomial (degree + 1)</param>
        /// <param name="inModuloBitSize"> BitSize of the prime modulo</param> 
        public Polynomial(BigInteger inPrimeModulo, uint inNumCoefficients, uint inModuloBitSize)
        {
            if (inNumCoefficients < 2) throw new ArgumentException("inNumCoefficients has to be greater or equal to 2");
            if(!Array.Exists(PublicKey.allowedSizes, element => element == inModuloBitSize)) throw new ArgumentException(string.Format("inModuloBitSize has to be in ( {0} )", string.Join(", ", PublicKey.allowedSizes)));

            PrimeModulo = inPrimeModulo;
            NumCoefficients = inNumCoefficients;
            ModuloBitSize = inModuloBitSize;
            Coefficients = new BigInteger[NumCoefficients];
            Rand = new SecretRandom();
        }


        /// <summary>
        /// Create the base polynomial
        /// </summary>
        /// <param name="inPrimeModulo"> Prime number of the finite group in byte </param>
        /// <param name="inNumCoefficients"> Number of coefficients of the polynomial (degree + 1)</param>
        /// <param name="inModuloBitSize"> BitSize of the prime modulo</param> 
        public Polynomial(byte[] inPrimeModulo, uint inNumCoefficients, uint inModuloBitSize) 
            : this(new BigInteger(1, inPrimeModulo), inNumCoefficients, inModuloBitSize) { }

        /// <summary>
        /// Create the base polynomial based on a SSS public key
        /// </summary>
        /// <param name="key"> SSS public key </param>
        public Polynomial(PublicKey key) : this(key.PrimeModulo,key.N, key.ModSize) { }

        /// <summary>
        /// Initialize the polynomial with random coefficients and the given 0th coefficient 
        /// </summary>
        /// <param name="zeroCoefficient"> 0th coefficient for the polynomial as a byte array</param>
        public void Init(byte[] zeroCoefficient)
        {
            BigInteger coefficient, tmpCoefficient;
            byte[] storage = new byte[ModuloBitSize / 8];

            coefficient = new BigInteger(1, zeroCoefficient);
            if (coefficient.CompareTo(PrimeModulo) != -1)
            {
                // destroy coefficient
                throw new ArgumentException("the given zeroCoefficient is bigger than the modulo");
            }

            for (int i = 1; i < Coefficients.Length; i++)
            {
                Rand.NextBytes(storage);
                tmpCoefficient = new BigInteger(1, storage);
                coefficient = tmpCoefficient.Mod(PrimeModulo);
                // destroy tmpCoefficient
                Coefficients[i] = coefficient;
            }

            // overwrite storage
            for (int i = 0; i < storage.Length; i++)
            {
                storage[i] = 0;
            }
        }


        /// <summary>
        /// Calculates the value of the polynomial at the given x-position 
        /// </summary>
        /// <param name="x"> x-position as a byte array</param>
        private byte[] CalculatePoint(byte[] x)
        {
            BigInteger Y, help1, help2;
            BigInteger X = new BigInteger(1, x);

            Y = Coefficients[0].Mod(PrimeModulo);
            for (int i = 1; i < Coefficients.Length; i++)
            {
                // a_i * x^i mod P
                help2 = Coefficients[i].Multiply(X.ModPow(new BigInteger(i.ToString()),PrimeModulo));
                help1 = Y.Add(help2);
                // destroy Y, help2
                Y = help1.Mod(PrimeModulo);
                // destroy help1
            }
            byte[] res = Y.ToByteArrayUnsigned();
            // destroy Y
            return res;
        }


        /// <summary>
        /// Calculates the values of the polynomial at the given x-positions
        /// </summary>
        /// <param name="xValues"> x-positions as a byte arrays. The array can't include 0 and every x-postion has to be unique</param>
        public byte[][] CalculatePoints(byte[][] xValues)
        {
            TestXValues(xValues); // throws exceptions
            byte[][] result = new byte[xValues.Length][];
            for (int i = 0; i < xValues.Length; i++)
            {
                result[i] = CalculatePoint(xValues[i]);
            }
            return result;

        }

        /// <summary>
        /// Test if the given x-positions are unique and don't contain x=0
        /// </summary>
        /// <param name="xValues"> x-positions as a byte arrays</param>
        private static void TestXValues(byte[][] xValues)
        { 
            for (int i = 0; i < xValues.Length - 1; i++)
            {
                if (new BigInteger(1, xValues[0]).Equals(BigInteger.Zero)) throw new ArgumentException(string.Format("xValues[{0}] is Zero", i));
                for (int j = i + 1; j < xValues.Length; j++)
                {
                    if (xValues[i].SequenceEqual(xValues[j])) throw new ArgumentException(string.Format("xValues {0} and {1} are identical", i, j));
                }
            }
        }


        /// <summary>
        /// Reconstructs the polynomial with the given Points and calculates the value at the given position.
        /// </summary>
        /// <param name="xValues"> x-positions as a byte arrays</param>
        /// <param name="yValues"> y-positions as a byte arrays</param>
        /// <param name="xPos"> x-positions to calculate polynomial value for</param>
        /// <param name="primeModulo"> prime modulo of the original polynom</param>
        public static byte[] Reconstruct(byte[][] xValues, byte[][] yValues, byte[] xPos, byte[] primeModulo)
        {
            BigInteger[] rel, yVals, xVals, xCoeffs;
            BigInteger help1, help2, ret;
            byte[] res;

            BigInteger bigPrimeModulo = new BigInteger(1, primeModulo);

            xVals = new BigInteger[xValues.Length];
            yVals = new BigInteger[xValues.Length];
            

            for (int i = 0; i < xValues.Length; i++)
            {
                xVals[i] = new BigInteger(1, xValues[i]);
                yVals[i] = new BigInteger(1, yValues[i]);
            }

            rel = RelativePosition(xVals, xPos);
            xCoeffs = XCoeff(xVals, rel, bigPrimeModulo);

            ret = BigInteger.Zero;
            for (int i = 0; i < xValues.Length; i++)
            {
                help1 = yVals[i].Multiply(xCoeffs[i]);
                help2 = help1.Mod(bigPrimeModulo);
                //Destroy help1, yVals[i]
                help1 = ret;
                ret = ret.Add(help2);
                // destroy help1,help2
            }
            help1 = ret;
            ret = ret.Mod(bigPrimeModulo);
            res = ret.ToByteArrayUnsigned();
            // destrox help1, ret
            return res;
        }

        /// <summary>
        /// Calculates the relative Positions of the given xValues to the xPosition
        /// </summary>
        /// <param name="xValues"> x-positions as a byte arrays</param>
        /// <param name="xPos"> x-positions to calculate polynomial value for</param>
        private static BigInteger[] RelativePosition(BigInteger[] xValues, byte[] xPos)
        {
            BigInteger X = new BigInteger(1, xPos);
            BigInteger[] res = new BigInteger[xValues.Length];
            for (int i = 0; i < xValues.Length; i++)
            {
                res[i] = X.Subtract(xValues[i]);
            }
            return res;
        }

        /// <summary>
        /// Calculates the Coefficients based on the x-positons of the points and the x-position to evaluate
        /// </summary>
        /// <param name="xValues"> x-positions as a byte arrays</param>
        /// <param name="rel"> relative distance of the evaluated position and the given x-Values</param>
        /// <param name="primeModulo"> prime modulo of the original polynomial</param>
        private static BigInteger[] XCoeff(BigInteger[] xValues, BigInteger[] rel, BigInteger primeModulo)
        {
            BigInteger[] res = new BigInteger[xValues.Length];
            BigInteger top, down;

            for (int i = 0; i < xValues.Length; i++)
            {
                top = BigInteger.One;
                down = BigInteger.One;
                for (int j = 0; j < xValues.Length; j++)
                {
                    if (i != j)
                    {
                        top = top.Multiply(rel[j]);
                        down = down.Multiply(xValues[i].Subtract(xValues[j]));
                    }
                }
                res[i] = top.Multiply(down.ModInverse(primeModulo)).Mod(primeModulo);
            }

            return res;
        }

        public void Destroy()
        {
            for (int i = 0; i < Coefficients.Length; i++)
            {
                // Destroy Coefficients
            }
            // Destroy Prime Modulo
        }
    }
}
