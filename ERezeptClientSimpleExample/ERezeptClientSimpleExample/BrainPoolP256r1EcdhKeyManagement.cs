using System;
using System.Collections.Generic;
using System.Text;
using Jose;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Arrays = Jose.Arrays;

namespace ERezeptClientSimpleExample {

    /// <summary>
    /// Plugin für jose-jwt um JWTs mit BrainPool-Curven zur PKI - Ver und Entschlüsselung zu nutzen
    /// </summary>
    public class BrainPoolP256r1EcdhKeyManagement : IKeyManagement {
        private readonly X9ECParameters _brainpoolP256R1 = ECNamedCurveTable.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256R1);
        const string BCRYPT_ALG_ID_HEADER = "alg";
        const string CRV = "BP-256";

        public virtual byte[][] WrapNewKey(int cekSizeBits, object externalPubKey, IDictionary<string, object> header) {
            var cek = NewKey(cekSizeBits, externalPubKey, header);
            var encryptedCek = Arrays.Empty;
            //Console.Out.WriteLine($"cek: {VAU.ByteArrayToHexString(cek)}");
            //Console.Out.WriteLine($"enc cek: {VAU.ByteArrayToHexString(encryptedCek)}");
            return new[] {cek, encryptedCek};
        }

        private byte[] NewKey(int keyLength, object externalPubKey, IDictionary<string, object> header) {
            // create ECDH-ES content encryption key
            // generate keypair for ECDH
            SecureRandom rnd = new SecureRandom();
            var keyGen = new ECKeyPairGenerator();
            var domainParams = new ECDomainParameters(_brainpoolP256R1.Curve, _brainpoolP256R1.G, _brainpoolP256R1.N, _brainpoolP256R1.H);
            var genParam = new ECKeyGenerationParameters(domainParams, rnd);
            keyGen.Init(genParam);
            var ecdhKeyPair = keyGen.GenerateKeyPair();
            var ephemeralPubkey = (ECPublicKeyParameters) ecdhKeyPair.Public;
            var ephemeralPrvKey = (ECPrivateKeyParameters) ecdhKeyPair.Private;

            header["epk"] = new Dictionary<string, object> {
                ["kty"] = "EC", 
                ["x"] = Base64Url.Encode(ephemeralPubkey.Q.XCoord.GetEncoded()),
                ["y"] = Base64Url.Encode(ephemeralPubkey.Q.YCoord.GetEncoded()), 
                ["crv"] = CRV
            };

            var deriveKey = DeriveKey(header, keyLength, externalPubKey as ECPublicKeyParameters, ephemeralPrvKey);
            //Console.Out.WriteLine($"dervied key (cek): {VAU.ByteArrayToHexString(deriveKey)}");

            return deriveKey;
        }

        static byte[] DeriveKey(IDictionary<string, object> header, int cekSizeBits, ECPublicKeyParameters externalPublicKey,
            ECPrivateKeyParameters ephemeralPrvKey) {
            var z = EcdhKeyAgreementZ(externalPublicKey, ephemeralPrvKey);

            var kdfGen = new ConcatenationKdfGenerator(new Sha256Digest());

            byte[] algId = Encoding.ASCII.GetBytes(header["enc"].ToString());
            byte[] apu = header.ContainsKey("apu") ? Base64Url.Decode((string) header["apu"]) : Arrays.Empty;
            byte[] apv = header.ContainsKey("apv") ? Base64Url.Decode((string) header["apv"]) : Arrays.Empty;
            byte[] kdl = CalcBeLengthArray(cekSizeBits);

            var otherInfo = Arrays.Concat(PrependLength(algId), PrependLength(apu), PrependLength(apv), kdl);
            //Console.Out.WriteLine($"otherInfo={VAU.ByteArrayToHexString(otherInfo)}");

            kdfGen.Init(new KdfParameters(z, otherInfo));
            byte[] secretKeyBytes = new byte[32];
            kdfGen.GenerateBytes(secretKeyBytes, 0, secretKeyBytes.Length);
            return secretKeyBytes;
        }

        static byte[] EcdhKeyAgreementZ(ECPublicKeyParameters externalPublicKey, ECPrivateKeyParameters ephemeralPrvKey) {
            var ecdh = new ECDHBasicAgreement();
            ecdh.Init(ephemeralPrvKey);

            var z = ecdh.CalculateAgreement(externalPublicKey);
            return BigIntegers.AsUnsignedByteArray(32, z);
        }

        static byte[] CalcBeLengthArray(int length) {
            var l = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(l);
            }
            return l;
        }

        static byte[] PrependLength(byte[] data) {
            return Arrays.Concat(CalcBeLengthArray(data.Length), data);
        }

        public virtual byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header) {
            throw new JoseException("(Direct) ECDH-ES key management cannot use existing CEK.");
        }

        public virtual byte[] Unwrap(byte[] encryptedCek, object privateKey, int cekSizeBits, IDictionary<string, object> header) {
            Ensure.Contains(header, new[] {"epk"}, "EcdhKeyManagement algorithm expects 'epk' key param in JWT header, but was not found");
            Ensure.Contains(header, new[] {BCRYPT_ALG_ID_HEADER},
                "EcdhKeyManagement algorithm expects 'enc' header to be present in JWT header, but was not found");

            var epk = (IDictionary<string, object>) header["epk"];

            Ensure.Contains(epk, new[] {"x", "y", "crv"},
                "EcdhKeyManagement algorithm expects 'epk' key to contain 'x','y' and 'crv' fields.");

            var x = new BigInteger(Base64Url.Decode(epk["x"].ToString()));
            var y = new BigInteger(Base64Url.Decode(epk["y"].ToString()));
            var externalPubKeyPoint = _brainpoolP256R1.Curve.CreatePoint(x, y);

            var domainParams = new ECDomainParameters(_brainpoolP256R1.Curve, _brainpoolP256R1.G, _brainpoolP256R1.N, _brainpoolP256R1.H);
            var externalPubKey = new ECPublicKeyParameters(externalPubKeyPoint, domainParams);

            return DeriveKey(header, cekSizeBits, externalPubKey, privateKey as ECPrivateKeyParameters);
        }
    }
}