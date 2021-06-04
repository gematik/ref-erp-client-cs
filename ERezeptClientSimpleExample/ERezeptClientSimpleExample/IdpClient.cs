using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml.Linq;
using ERezeptClientSimpleExample.AuthSignatureService;
using ERezeptClientSimpleExample.CertificateService;
using ERezeptClientSimpleExample.EventService;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ERezeptClientSimpleExample {
    public class IdpClient {
        readonly string _httpsKonInstanz2TitusTiDiensteDeConnectorSds; //ServiceVerzeichnis vom Konnektor, der bei Authentifizierung zum IDP hilft
        readonly X509Certificate2 _connectorCommunikationCert; //Client-Zertifikat für die Kommunikation mit dem lokalen Konnektor des PS

        readonly string _idpserver; //URL/IP zum IDP 
        readonly string _userAgent; //User Agent für alle HTTP Requests zum IDP und EREzept-Server
        readonly string _clientId; //Die client_id des Clients. Wird bei der Registrierung vergeben.
        readonly string _redirectUri; //Die für den Client beim Server hinterlegte redirect_uri. Muss dem bei der Registrierung hinterlegten Wert entsprechen.

        //Konnektor-Context Information für alle Konnektor Webservice-Calls
        readonly string _clientSystemId4Context;
        readonly string _workplaceId4Context;
        readonly string _mandantId4Context;

        readonly SecureRandom _random = new();
        readonly (string EventServiceUrl, string CertificateServiceUrl, string AuthsignatureServiceUrl) _konnectorServiceUrls;
        readonly HttpClient _httpClientDefault;

        public IdpClient(string httpsKonInstanz2TitusTiDiensteDeConnectorSds, string userAgent, string idpserver, string clientId, string redirectUri, X509Certificate2 connectorCommunikationCert, string clientSystemId4Context, string workplaceId4Context, string mandantId4Context) {
            _httpsKonInstanz2TitusTiDiensteDeConnectorSds = httpsKonInstanz2TitusTiDiensteDeConnectorSds;
            _userAgent = userAgent;
            _idpserver = idpserver;
            _clientId = clientId;
            _redirectUri = redirectUri;
            _connectorCommunikationCert = connectorCommunikationCert;
            _clientSystemId4Context = clientSystemId4Context;
            _workplaceId4Context = workplaceId4Context;
            _mandantId4Context = mandantId4Context;

            _httpClientDefault = new HttpClient();
            _httpClientDefault.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);

            _konnectorServiceUrls = LocateKonnektorServiceUrls();
        }

        /// <summary>
        /// gibt einen für 300 sek gültiges Token zurück
        /// Vorgehen nach: https://gematik.github.io/ref-idp-server/tokenFlowPs.html / https://github.com/gematik/ref-idp-server
        /// </summary>
        /// <param name="tokenForApothekeWhenMultipleSmcbFound">true -> wenn mehrere SMCBs im Konnektor stecken, wird bevorzugt eine Apo-SMCB genommen; false -> bevorzugt Arzt-SMCB</param>
        /// <returns>null bei Fehlern</returns>
        public string GetBearerToken(bool tokenForApothekeWhenMultipleSmcbFound) {
            string CreateRandomCodeverifier() {
                //https://tools.ietf.org/html/rfc7636#section-4.1
                return Base64Url.Encode(_random.GenerateSeed(60));
            }

            //gemSpec_IDP_Frontend A_20309
            string codeVerifier = CreateRandomCodeverifier();
            Console.Out.WriteLine($"CODE_VERIFIER={codeVerifier}");

            string codeChallenge = Base64Url.Encode(Sha265HashAscii(codeVerifier));
            Console.Out.WriteLine($"CODE_CHALLENGE={codeChallenge}");

            //IDP get DD
            string DD_jwt = _httpClientDefault.GetStringAsync($"{_idpserver}/.well-known/openid-configuration").Result; 
            var DD_jwt_headers = JWT.Headers(DD_jwt);

            var x5c = ((object[]) DD_jwt_headers["x5c"])[0].ToString();
            var idp_dd_sig_cert = new X509Certificate2(Encoding.UTF8.GetBytes(x5c));


            //HACK invalid DD signature (weiter unten funktioniert der Code perfekt mit anderer signatur) !!! -> TITUS BUG
            ECPublicKeyParameters zertKey = RetrievePubKeyFromCert(idp_dd_sig_cert);
            try {
                string payload = JWT.Decode(DD_jwt, zertKey, JwsAlgorithm.ES256,
                    new JwtSettings().RegisterJws(JwsAlgorithm.ES256, new BrainPoolP256r1JwsAlgorithm()).RegisterJwsAlias("BP256R1", JwsAlgorithm.ES256));
            } catch (Exception exception) {
                Console.WriteLine(exception);
            }

            var DD_json = JWT.Payload(DD_jwt);
            var DD = JObject.Parse(DD_json);
            Console.Out.WriteLine($"DD={DD_json}");

            //gemSpec_IDP_Frontend A_20483: IDP get challenge
            Console.Out.WriteLine($"auth endpoint={DD["authorization_endpoint"]}");

            var httpParams = new[] {
                ("scope", "e-rezept%20openid"),
                ("response_type", "code"),
                ("client_id", _clientId),
                ("state", "1234"), //??
                ("code_challenge", codeChallenge),
                ("code_challenge_method", "S256"),
                ("redirect_uri", _redirectUri)
            };

            var requestUri = $"{DD["authorization_endpoint"]}?{string.Join("&", httpParams.Select(x => $"{x.Item1}={x.Item2}"))}";
            Console.Out.WriteLine(requestUri);
            var response = _httpClientDefault.GetAsync(requestUri).Result;

            if (!response.IsSuccessStatusCode) {
                Console.WriteLine($"{(int) response.StatusCode} ({response.ReasonPhrase})");
                Console.Out.WriteLine($"Response body: {response.Content.ReadAsStringAsync().Result}");
                return null;
            }

            Console.Out.WriteLine("challenge erfolgreich");

            var getChallengeResponseString = response.Content.ReadAsStringAsync().Result;
            var getChallengeResponseJson = JObject.Parse(getChallengeResponseString);
            Console.Out.WriteLine($"GET Challenge response={getChallengeResponseJson}");

            // GET IDP Sig Cert to validate Challenge
            var pukiUriSig = DD["uri_puk_idp_sig"].ToString();
            string sigCertX5C = _httpClientDefault.GetStringAsync(pukiUriSig).Result;
            var sigCertString = JObject.Parse(sigCertX5C)["x5c"].FirstOrDefault()?.ToString();
            // ReSharper disable once AssignNullToNotNullAttribute
            var idp_token_sig_cert = new X509Certificate2(Encoding.UTF8.GetBytes(sigCertString));
            Console.Out.WriteLine($"SigCert={idp_token_sig_cert.SubjectName}");

            //Verify signature of challengeJwtString
            ECPublicKeyParameters zertKey2 = RetrievePubKeyFromCert(idp_token_sig_cert);
            JObject challengeTokenPayload = JObject.Parse(JWT.Decode($"{getChallengeResponseJson["challenge"]}", zertKey2, JwsAlgorithm.ES256,
                new JwtSettings().RegisterJws(JwsAlgorithm.ES256, new BrainPoolP256r1JwsAlgorithm())
                    .RegisterJwsAlias("BP256R1", JwsAlgorithm.ES256)));

            // create nested jwt with challenge included
            CardInfoType[] smcbs = GetKonnektorSMCBs();

            var smcbsCertificates = readAutCerts(smcbs);

            var smcbAuthCert = smcbsCertificates.FirstOrDefault(l=>l.apotheke==tokenForApothekeWhenMultipleSmcbFound);
            if (smcbAuthCert == default) {
                throw new ArgumentException($"SMCB für Apotheke={tokenForApothekeWhenMultipleSmcbFound} nicht gefunden");
            }

            Console.Out.WriteLine($"SMC.AUT={smcbAuthCert.certificate.SubjectName.Name}, alg: {smcbAuthCert.certificate.GetKeyAlgorithm()}");
            var smcbAuthCertB64 = new[] {Convert.ToBase64String(smcbAuthCert.certificate.RawData)};
            Console.Out.WriteLine($"SMC.AUT(b64)={smcbAuthCertB64[0]}");

            var njwtHeadersB64 =
                Base64Url.Encode(Encoding.UTF8.GetBytes(new JObject {
                    ["alg"] = smcbAuthCert.certificate.SignatureAlgorithm.FriendlyName == "sha256RSA" ? "PS256" : "BP256R1", //, // je nach SMC-B ggf. auch BP256R1 
                    ["cty"] = "NJWT",
                    ["x5c"] = JToken.FromObject(smcbAuthCertB64),
                }.ToString(Formatting.None)));
            var njwtPayloadB64 =
                Base64Url.Encode(Encoding.UTF8.GetBytes(new JObject {["njwt"] = getChallengeResponseJson["challenge"]}.ToString(Formatting.None)));

            // sign nested jwt
            var headerPayloadString = $"{njwtHeadersB64}.{njwtPayloadB64}";
            var bytesToHash = Encoding.UTF8.GetBytes(headerPayloadString);

            // Create a SHA256  
            var digester = new SHA256Managed();
            byte[] sha265Digest = digester.ComputeHash(bytesToHash);

            // sign
            var sig = externalAuthenticate(sha265Digest, smcbAuthCert.cardhandle);
            var jws = $"{njwtHeadersB64}.{njwtPayloadB64}.{Base64Url.Encode(sig)}";
            Console.Out.WriteLine($"to Hash (String) : {headerPayloadString}");
            Console.Out.WriteLine($"njwtHash ={VAU.ByteArrayToHexString(sha265Digest)}");
            Console.Out.WriteLine($"jws: {jws}");

            // create JWE with JWS nested
            var jwePayloadJson = new JObject {["njwt"] = jws}.ToString(Formatting.None);
            Console.Out.WriteLine($"jwePayload: {jwePayloadJson}");

            ECPublicKeyParameters idpEncKeyPublic = RetrieveIdpPubKey(DD["uri_puk_idp_enc"].ToString());

            long exp = long.Parse(challengeTokenPayload["exp"].ToString());
            string jwe = JWT.Encode(jwePayloadJson, idpEncKeyPublic, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM,
                settings : new JwtSettings().RegisterJwa(JweAlgorithm.ECDH_ES, new BrainPoolP256r1EcdhKeyManagement()),
                extraHeaders : new Dictionary<string, object> {
                    {"exp", exp},
                    {"cty", "NJWT"},
                });
            Console.Out.WriteLine($"jwe: {jwe}");

            // Content-Type: application/x-www-form-urlencoded'
            // signed_challenge=JWE
            var handler = new HttpClientHandler // don't follow redirect
            {
                AllowAutoRedirect = false
            };
            var cl3 = new HttpClient(handler);
            cl3.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);

            var response2 = cl3.PostAsync(
                $"{DD["authorization_endpoint"]}", new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("signed_challenge", jwe)
                })).Result;

            if (!response2.StatusCode.Equals(HttpStatusCode.Redirect)) {
                Console.WriteLine($"Error: {(int) response2.StatusCode} ({response2.ReasonPhrase})");
                Console.Out.WriteLine($"Response body: {response2.Content.ReadAsStringAsync().Result}");
                return null;
            }

            Console.Out.WriteLine($"AC: {response2.Headers.Location}"); //Param Code lesen
            var values = HttpUtility.ParseQueryString(response2.Headers.Location.Query);
            var code = values["code"];
            Console.Out.WriteLine($"Response body: {response2.Content.ReadAsStringAsync().Result}");
            Console.Out.WriteLine("erfolgreich");

            //und nun das Token abholen

            //JWE, welches den code_verifier sowie den token_key enthält. Dies ist ein AES-Schlüssel welcher vom Server zur Verschlüsselung der Token-Rückgaben verwendet wird.
            //Enthalten ist der code_verifier (der zu dem code_challenge-Wert aus der initialen Anfrage passen muss) sowie der token_key. Dies ist ein vom Client zufällig gewürfelter AES256-Schlüssel in Base64-URL-Encoding. Der Server benutzt diesen Schlüssel zur Chiffrierung der beiden Token-Rückgaben in der Response (ID- und Access-Token).
            // ReSharper disable once RedundantAssignment
            byte[] rawAesTokenKey = new byte[32];
            _random.NextBytes(rawAesTokenKey);
            rawAesTokenKey = Base64Url.Decode("D9ccZA6pUTIoaxHqvl9nbxs6AqkT93Leg43rFwslce8"); //HACK wegen Exception vom Server -> TITUS BUG
            string tokenaeskey = Base64Url.Encode(rawAesTokenKey);

            var key_verifier_jwe_payload_json =
                new JObject {["token_key"] = tokenaeskey, ["code_verifier"] = codeVerifier}.ToString(Formatting.None);
            Console.Out.WriteLine($"key_verifier_jwe_payload_json: {key_verifier_jwe_payload_json}");

            string key_verifier_jwe = JWT.Encode(key_verifier_jwe_payload_json, idpEncKeyPublic, JweAlgorithm.ECDH_ES,
                JweEncryption.A256GCM,
                settings : new JwtSettings().RegisterJwa(JweAlgorithm.ECDH_ES, new BrainPoolP256r1EcdhKeyManagement()),
                extraHeaders : new Dictionary<string, object> {
                    {"exp", exp},
                    {"cty", "NJWT"},
                });

            //z.B. http://url.des.idp/token
            var cltoken = new HttpClient();
            cltoken.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);
            cltoken.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //gemSpec_IDP_Frontend A_20529
            var responsetoken = cltoken.PostAsync(
                $"{DD["token_endpoint"]}", new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("key_verifier", key_verifier_jwe),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("redirect_uri", _redirectUri),
                    new KeyValuePair<string, string>("client_id", _clientId),
                })).Result;

            //gemSpec_IDP_Frontend A_19938 A_20283
            if (!responsetoken.IsSuccessStatusCode) {
                Console.Out.WriteLine($"{(int) responsetoken.StatusCode} ({responsetoken.ReasonPhrase})");
                Console.Out.WriteLine($"Response body PostToken: {responsetoken.Content.ReadAsStringAsync().Result}");
                return null;
            }

            string responseString = responsetoken.Content.ReadAsStringAsync().Result;
            Console.Out.WriteLine($"Response body: {responseString}");
            Console.Out.WriteLine("erfolgreich");

            var tokenResponseJson = JObject.Parse(responseString);
            //string bearerenc = tokenResponseJson["id_token"].ToString();
            string access_token_encrypted = tokenResponseJson["access_token"].ToString();

            var access_token = JObject.Parse(JWT.Decode(access_token_encrypted, rawAesTokenKey, JweAlgorithm.DIR,
                JweEncryption.A256GCM))["njwt"];
            Console.Out.WriteLine($"access_token: {access_token}");

            return access_token.ToString();
        }

        private (string cardhandle, X509Certificate2 certificate, bool apotheke)[] readAutCerts(CardInfoType[] smcbs) {
            var service =
                ServiceEndpointFactory.CreateEndpoint<CertificateServicePortTypeClient, CertificateServicePortType>(_konnectorServiceUrls
                    .CertificateServiceUrl);
            // ReSharper disable once PossibleNullReferenceException
            service.ClientCredentials.ClientCertificate.Certificate = _connectorCommunikationCert;

            return smcbs.Select(smcb => {

                var resp = service.ReadCardCertificate(new ReadCardCertificate {
                    CardHandle = smcb.CardHandle,
                    CertRefList = new[] {
                        ReadCardCertificateCertRef.CAUT,
                    },
                    Context = new CertificateService.ContextType {
                        ClientSystemId = _clientSystemId4Context,
                        WorkplaceId = _workplaceId4Context,
                        MandantId = _mandantId4Context,
                    }
                });

                var cert = new X509Certificate2(resp.X509DataInfoList[0].X509Data.X509Certificate);
                bool apotheke = Encoding.UTF8.GetString(cert.Extensions["1.3.36.8.3.3"]?.RawData??new byte[0]).Contains("Öffentliche Apotheke");

                return (smcb.CardHandle, cert, apotheke);

            }).ToArray();
        }

        private CardInfoType[] GetKonnektorSMCBs() {
            var service =
                ServiceEndpointFactory.CreateEndpoint<EventServicePortTypeClient, EventServicePortType>(_konnectorServiceUrls
                    .EventServiceUrl);
            // ReSharper disable once PossibleNullReferenceException
            service.ClientCredentials.ClientCertificate.Certificate = _connectorCommunikationCert;
            GetCardsResponse cards = service.GetCards(new GetCards {
                CardType = CardTypeType.SMCB,
                CardTypeSpecified = true,
                Context = new EventService.ContextType {
                    ClientSystemId = _clientSystemId4Context,
                    WorkplaceId = _workplaceId4Context,
                    MandantId = _mandantId4Context,
                }
            });
            return cards.Cards;
        }

        private (string EventServiceUrl, string CertificateServiceUrl, string AuthsignatureServiceUrl) LocateKonnektorServiceUrls() {
            //Titus Konnektor Clientzert nutzen
            HttpClient client = new HttpClient(new HttpClientHandler {
                ClientCertificates = {_connectorCommunikationCert},
                ClientCertificateOptions = ClientCertificateOption.Manual
            });
            client.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);


            string sds = client.GetStringAsync(_httpsKonInstanz2TitusTiDiensteDeConnectorSds).Result;

            //Console.Out.WriteLine("erfolgreich = " + sds);

            var doc = XDocument.Parse(sds);
            var certificateServiceUrl = doc.Root?.DescendantsAndSelf()
                .FirstOrDefault(n => n.Name.LocalName == "Service" && n.Attribute("Name")?.Value == "CertificateService")
                ?.DescendantsAndSelf().FirstOrDefault(n => n.Name.LocalName == "EndpointTLS")?.Attribute("Location")?.Value;
            Console.Out.WriteLine($"certificateServiceUrl={certificateServiceUrl}");

            var signatureServiceUrl = doc.Root?.DescendantsAndSelf()
                .FirstOrDefault(n => n.Name.LocalName == "Service" && n.Attribute("Name")?.Value == "SignatureService")
                ?.DescendantsAndSelf().FirstOrDefault(n => n.Name.LocalName == "EndpointTLS")?.Attribute("Location")?.Value;
            Console.Out.WriteLine($"signatureServiceUrl={signatureServiceUrl}");

            var authsignatureServiceUrl = doc.Root?.DescendantsAndSelf()
                .FirstOrDefault(n => n.Name.LocalName == "Service" && n.Attribute("Name")?.Value == "AuthSignatureService")
                ?.DescendantsAndSelf().FirstOrDefault(n => n.Name.LocalName == "EndpointTLS")?.Attribute("Location")?.Value;
            Console.Out.WriteLine($"authsignatureServiceUrl={authsignatureServiceUrl}");

            var eventServiceUrl = doc.Root?.DescendantsAndSelf()
                .FirstOrDefault(n => n.Name.LocalName == "Service" && n.Attribute("Name")?.Value == "EventService")?.DescendantsAndSelf()
                .FirstOrDefault(n => n.Name.LocalName == "EndpointTLS")?.Attribute("Location")?.Value;
            Console.Out.WriteLine($"eventServiceUrl={eventServiceUrl}");
            return (EventServiceUrl : eventServiceUrl, CertificateServiceUrl : certificateServiceUrl,
                AuthsignatureServiceUrl : authsignatureServiceUrl);
        }

        private byte[] externalAuthenticate(byte[] sha265Hash, string smcbCardHandle) {
            var service =
                ServiceEndpointFactory.CreateEndpoint<AuthSignatureServicePortTypeClient, AuthSignatureServicePortType>(
                    _konnectorServiceUrls.AuthsignatureServiceUrl);
            // ReSharper disable once PossibleNullReferenceException
            service.ClientCredentials.ClientCertificate.Certificate = _connectorCommunikationCert;

            var respex = service.ExternalAuthenticate(
                new ExternalAuthenticate {
                    CardHandle = smcbCardHandle, /* HACK TITUS-BUG OptionalInputs führen derzeit zu einer Exception
                    OptionalInputs = new ExternalAuthenticateOptionalInputs {
                        SignatureSchemes = SignatureSchemes.RSASSAPSS,
                        SignatureSchemesSpecified = true,
                        SignatureType = "urn:ietf:rfc:3447",
                    }, */
                    BinaryString = new BinaryDocumentType {
                        Base64Data = new Base64Data {
                            MimeType = "application/octet-stream",
                            Value = sha265Hash,
                        }
                    },
                    Context = new AuthSignatureService.ContextType {
                        ClientSystemId = _clientSystemId4Context,
                        WorkplaceId = _workplaceId4Context,
                        MandantId = _mandantId4Context,
                    }
                });

            var sig = (respex.SignatureObject.Item as Base64Signature)?.Value;
            Console.Out.WriteLine(VAU.ByteArrayToHexString(sig));

            return sig;
        }

        static ECPublicKeyParameters RetrievePubKeyFromCert(X509Certificate2 cert) {
            var z = cert.GetECDsaPublicKey();
            var p = z.ExportParameters(false);

            X9ECParameters x9EC = ECNamedCurveTable.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256R1);
            ECDomainParameters domainParams = new ECDomainParameters(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());

            var x = new BigInteger(1, p.Q.X);
            var y = new BigInteger(1, p.Q.Y);
            var idpEcPoint = domainParams.Curve.CreatePoint(x, y);

            return new ECPublicKeyParameters(idpEcPoint, domainParams);
        }


        ECPublicKeyParameters RetrieveIdpPubKey(string url) {
            var idpEncKeyJson = JObject.Parse(_httpClientDefault.GetStringAsync(url).Result);
            Console.Out.WriteLine($"idpEncKeyJson: {idpEncKeyJson["x"]} {idpEncKeyJson["y"]}");

            X9ECParameters x9EC = ECNamedCurveTable.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256R1);
            ECDomainParameters domainParams = new ECDomainParameters(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());

            var x = new BigInteger(1, Base64Url.Decode(idpEncKeyJson["x"].ToString()));
            var y = new BigInteger(1, Base64Url.Decode(idpEncKeyJson["y"].ToString()));
            var idpEcPoint = domainParams.Curve.CreatePoint(x, y);

            return new ECPublicKeyParameters(idpEcPoint, domainParams);
        }

        private static byte[] Sha265HashAscii(string codeVerifier) {
            var z = new Sha256Digest();
            var bytes = Encoding.ASCII.GetBytes(codeVerifier);
            z.BlockUpdate(bytes, 0, bytes.Length);
            var sha265Hash = new byte[32];
            var f = z.DoFinal(sha265Hash, 0); //f==32
            if (f != 32) {
                throw new ArgumentException("Fehler bei Sha265HashAscii -> muss 32 sein");
            }
            return sha265Hash;
        }
    }
}