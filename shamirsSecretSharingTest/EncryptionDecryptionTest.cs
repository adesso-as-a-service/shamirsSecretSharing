using Microsoft.VisualStudio.TestTools.UnitTesting;
using shamirsSecretSharing;
using System;
using System.Linq;
namespace shamirsSecretSharingTest
{
    [TestClass]
    public class EncryptionDecryptionTest
    {

        private Random rnd = new Random();

        [TestMethod]
        public void Encrypt()
        {
            byte[] secret;
            PublicKey pub = new PublicKey(3, 5, 3072);
            SssEngine engine = new SssEngine(pub);
            secret = new byte[120];
            rnd.NextBytes(secret);
            Tuple<PublicKey,Share[]>ret = engine.Encrypt(secret);
        }

        [TestMethod]
        public void Decrypt()
        {
            byte[] secret;
            PublicKey pub = new PublicKey(3, 5, 3072);
            SssEngine engine = new SssEngine(pub);
            secret = new byte[120];
            secret[0] = 0x1;
            rnd.NextBytes(secret);
            Tuple<PublicKey, Share[]> ret = engine.Encrypt(secret);
            byte[] res = SssEngine.Decrypt(pub, ret.Item2);
            Assert.IsTrue(res.SequenceEqual(secret));
        }
    }
}
