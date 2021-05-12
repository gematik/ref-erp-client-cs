using System;
using System.Security.Cryptography;
using Jose;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace ERezeptClientSimpleExample {
    /// <summary>
    /// Plugin für jose-jwt um JWTs mit BrainPool-Curven zur Signaturprüfung zu nutzen Signaturerstellung ist derzeit nicht umgesetzt
    /// </summary>
    public class BrainPoolP256r1JwsAlgorithm : IJwsAlgorithm {
        public byte[] Sign(byte[] securedInput, object key) {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key) {
            if (key is not ECPublicKeyParameters publicKey) {
                throw new ArgumentException("key must be ECPublicKeyParameters");
            }
            ECCurve brainpoolP256R1 = ECCurve.NamedCurves.brainpoolP256r1;

            var dsa = ECDsa.Create(new ECParameters {
                Curve = brainpoolP256R1,
                Q = new ECPoint {
                    X = BigIntegers.AsUnsignedByteArray(publicKey.Q.XCoord.ToBigInteger()),
                    Y = BigIntegers.AsUnsignedByteArray(publicKey.Q.YCoord.ToBigInteger()),
                },
            });

            return dsa.VerifyData(securedInput, signature, HashAlgorithmName.SHA256);
        }
    }
}