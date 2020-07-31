using System;
using System.Dynamic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using net.vieapps.Components.Utility;
using Open.Numeric.Primes;

namespace did_security_csharp
{
    /**
     * Class to model a pairwise key
     * Reference implementation for EC pairwise keys and RSA pairwise keys
     */
    public class PairwiseKey
    {
        /// <summary>
        /// Gets or sets the did
        /// </summary>
        public string Did { get; set; }

        /// <summary>
        /// Gets or sets the peer id
        /// </summary>
        public string PeerId { get; set; }

        /// <summary>
        ///  Create an instance of PairwiseKey.
        /// </summary>
        /// <param name="did">The DID</param>
        /// <param name="peerId">The peer id</param>
        public PairwiseKey(string did, string peerId)
        {
            this.Did = did;
            this.PeerId = peerId;
        }

        /// <summary>
        /// Generate the pairwise Key.
        /// </summary>
        /// <param name="seed">Seed for the generating DID master keys.</param>
        /// <param name="keySize">Key size. Only applicable for RSA</param>
        /// <param name="keyType">Key type.</param>
        /// <returns>The pairwise key</returns>
        public object generate(byte[] seed, int keySize, string keyType)
        {
            switch (keyType.ToUpper())
            {
                case "EC":
                    return this.generateEcPairwiseKey(seed);
                case "RSA":
                    return this.generateRsaPairwiseKey(seed, keySize);
            }

            throw new NotImplementedException($"Pairwise key for key type ${keyType} is not supported");
        }

        /// <summary>
        /// Generate the master Key.
        /// </summary>
        /// <param name="seed">Seed for the generating DID master keys.</param>
        /// <param name="did">The DID</param>
        /// <param name="peerId">The peer id</param>
        /// <returns>DID master key</returns>
        private byte[] generateDidMasterKey(byte[] seed, string did, string peerId)
        {
            byte[] didBytes = Encoding.UTF8.GetBytes(did + "signature");

            // Initialize the keyed hash object.
            byte[] hashValue = null;
            using (HMACSHA512 hmac = new HMACSHA512(seed))
            {
                hashValue = hmac.ComputeHash(didBytes);
            }

            return hashValue;
        }

        /// <summary>
        /// Convert big endian array to little endian
        /// </summary>
        /// <param name="toConvert"></param>
        /// <returns>Converted array</returns>
        private byte[] ConvertToLittleEndian(byte[] toConvert)
        {
            byte[] littleEndian = new byte[toConvert.Length + 1];
            for (int convertedInx = 0, toConvertInx = toConvert.Length - 1; convertedInx < toConvert.Length; convertedInx++, toConvertInx--)
            {
                littleEndian[convertedInx] = toConvert[toConvertInx];
            }

            // make sure to return a positive number
            littleEndian[toConvert.Length] = 0;

            return littleEndian;
        }

        /// <summary>
        /// Convert little endian to big endian
        /// </summary>
        /// <param name="toConvert"></param>
        /// <returns>Converted array</returns>
        private byte[] ConvertToBigEndian(byte[] toConvert, int wantedSize)
        {
            try
            {
                byte[] bigEndian = new byte[wantedSize];

                int toConvertInx = toConvert.Length - 1;
                if (toConvert.Length > wantedSize)
                {
                    toConvertInx = toConvert.Length - (toConvert.Length - wantedSize) - 1;
                }
                else if (toConvert.Length < wantedSize)
                {
                    bigEndian = new byte[toConvert.Length];
                    wantedSize = toConvert.Length;
                }

               
                for (int convertedInx = 0; convertedInx < wantedSize; convertedInx++, toConvertInx--)
                {
                    if (convertedInx >= toConvert.Length)
                    {
                        bigEndian[convertedInx] = 0;
                    }
                    else
                    {
                        bigEndian[convertedInx] = toConvert[toConvertInx];
                    }
                }

                return bigEndian;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private string ToBase64Url(byte[] toConvert)
        {
            string b64 = Convert.ToBase64String(toConvert);
            return b64.Split('=')[0].Replace('+', '-').Replace('/', '_');
        }

        /// <summary>
        /// Loop until a probable prime is found.
        /// Based on the Miller Rabin primility test with 64 loops to be deterministic
        /// </summary>
        /// <param name="prime"></param>
        /// <returns>Prime number</returns>
        private BigInteger GetPrime(BigInteger prime)
        {
            int count = 1;
            BigInteger two = new BigInteger(2);
            while (true)
            {
                if (MillerRabin.IsProbablePrime(prime, 64))
                {
                    Console.WriteLine("Number of rounds: {0}", count);
                    return prime;
                }

                prime += two;
                count++;
            }
        }

        /// <summary>
        /// Generate a starting number for prime testing based on signatures
        /// The number is deterministic.
        /// </summary>
        /// <param name="key">Seed</param>
        /// <param name="primeSize">Number of bits</param>
        /// <param name="data">Data to sign</param>
        /// <returns></returns>
        private byte[] generateDeterministicNumberForPrime(byte[] key, int primeSize, byte[] data)
        {
            int nrRounds = primeSize / 512;
            byte[] result = new byte[primeSize / 8];
            int destInx = 0;
            while (nrRounds-- > 0)
            {
                using (HMACSHA512 hmac = new HMACSHA512(key))
                {
                    byte[] number = hmac.ComputeHash(data);
                    Buffer.BlockCopy(number, 0, result, destInx, number.Length);
                    data = number;
                    destInx += number.Length;
                }
            }

            return result;
        }

        /// <summary>
        /// Generate the RSA pairwise Key.
        /// </summary>
        /// <param name="seed">Seed for the generating DID master keys.</param>
        /// <param name="keySize">Key size</param>
        /// <returns>Json Web Key</returns>
        private object generateRsaPairwiseKey(byte[] seed, int keySize)
        {
            // Generate DID master key
            byte[] didMasterKey = this.generateDidMasterKey(seed, this.Did, this.PeerId);

            // Generate peer key
            byte[] peerId = Encoding.UTF8.GetBytes(this.PeerId);

            // Get pbase
            byte[] pbase = this.generateDeterministicNumberForPrime(didMasterKey, keySize / 2, peerId);

            // Get qbase
            byte[] qbase = this.generateDeterministicNumberForPrime(pbase, keySize / 2, peerId);

            // Set most and least significant bit
            pbase[0] |= 0x80;
            pbase[pbase.Length - 1] |= 0x1;
            qbase[0] |= 0x80;
            qbase[qbase.Length - 1] |= 0x1;

            // base components for key generation
            pbase = this.ConvertToLittleEndian(pbase);
            qbase = this.ConvertToLittleEndian(qbase);

            // Generate key pair
            BigInteger p = new BigInteger(pbase);
            p = this.GetPrime(p);
            BigInteger q = new BigInteger(qbase);
            q = this.GetPrime(q);
            BigInteger n = BigInteger.Multiply(p, q);
            BigInteger e = new BigInteger(65537);
            var pMinus = BigInteger.Subtract(p, BigInteger.One);
            var qMinus = BigInteger.Subtract(q, BigInteger.One);
            var phi = BigInteger.Multiply(pMinus, qMinus);
            var d = e.ModInverse(phi);
            var dp = BigInteger.ModPow(d, 1, pMinus);
            var dq = BigInteger.ModPow(d, 1, qMinus);
            var qi = q.ModInverse(p);

            // Convert to big endian
            var jwke = this.ConvertToBigEndian(e.ToByteArray(), 3);
            var jwkn = this.ConvertToBigEndian(n.ToByteArray(), 128);
            var jwkd = this.ConvertToBigEndian(d.ToByteArray(), 128);
            var jwkp = this.ConvertToBigEndian(p.ToByteArray(), 64);
            var jwkq = this.ConvertToBigEndian(q.ToByteArray(), 64);
            var jwkdp = this.ConvertToBigEndian(dp.ToByteArray(), 64);
            var jwkdq = this.ConvertToBigEndian(dq.ToByteArray(), 64);
            var jwkqi = this.ConvertToBigEndian(qi.ToByteArray(), 64);

            // Set json web key
            dynamic jwk = new ExpandoObject();
            jwk.kty = "RSA";
            jwk.e = this.ToBase64Url(jwke);
            jwk.n = this.ToBase64Url(jwkn);
            jwk.d = this.ToBase64Url(jwkd);
            jwk.p = this.ToBase64Url(jwkp);
            jwk.q = this.ToBase64Url(jwkq);
            jwk.dp = this.ToBase64Url(jwkdp);
            jwk.dq = this.ToBase64Url(jwkdq);
            jwk.qi = this.ToBase64Url(jwkqi);
            return jwk;
        }

        /// <summary>
        /// Generate the EC pairwise Key.
        /// </summary>
        /// <param name="seed">Seed for the generating DID master keys.</param>
        /// <returns>Json Web Key</returns>
        private object generateEcPairwiseKey(byte[] seed)
        {
            // Generate DID master key
            byte[] didMasterKey = this.generateDidMasterKey(seed, this.Did, this.PeerId);

            // Generate peer key
            byte[] peerId = Encoding.UTF8.GetBytes(this.PeerId);

            // Initialize the keyed hash object.
            byte[] hashValue = null;
            using (HMACSHA512 hmac = new HMACSHA512(didMasterKey))
            {
                hashValue = hmac.ComputeHash(peerId);
            }
            byte[] littleEndian = this.ConvertToLittleEndian(hashValue);
            BigInteger privKey = new BigInteger(littleEndian);
            privKey %= ECCsecp256k1.N;

            var pubKey = ECCsecp256k1.G.Multiply(privKey);
            var d = this.ConvertToBigEndian(privKey.ToByteArray(), 32);
            var x = this.ConvertToBigEndian(pubKey.X.ToByteArray(), 32);
            var y = this.ConvertToBigEndian(pubKey.Y.ToByteArray(), 32);
            dynamic jwk = new ExpandoObject();
            jwk.crv = "secp256k1";
            jwk.d = this.ToBase64Url(d);
            jwk.x = this.ToBase64Url(x);
            jwk.y = this.ToBase64Url(y);
            return jwk;
        }
    }
}
