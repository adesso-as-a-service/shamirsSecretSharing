using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    }
}
