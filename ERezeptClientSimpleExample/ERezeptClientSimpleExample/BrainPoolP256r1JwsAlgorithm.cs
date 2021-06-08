using System;
using System.Linq;
using Jose;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

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
         
            ISigner signer = SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256.Id);
            signer.Init(false, publicKey);
            signer.BlockUpdate(securedInput, 0, securedInput.Length);

            var derSignature = new DerSequence(
                    // first 32 bytes is "r" number
                    new DerInteger(new BigInteger(1, signature.Take(32).ToArray())),
                    // last 32 bytes is "s" number
                    new DerInteger(new BigInteger(1, signature.Skip(32).ToArray())))
                .GetDerEncoded();

           var verifySignature = signer.VerifySignature(derSignature);
           return verifySignature;
        }
    }
}