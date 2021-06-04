using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ERezeptClientSimpleExample {
    class Program {

        /// <summary>
        /// URLs aus TITUS Onlinehilfe (Titus emuliert sowohl einen PS Konnektor als auch IDP und Fachdienst)
        /// </summary>
        const string IDP_SERVER_URL = "https://idp.erezept-instanz1.titus.ti-dienste.de";
        const string EREZEPT_FACHDIENST_URL = "https://fd.erezept-instanz1.titus.ti-dienste.de";
        const string PS_KONNEKTOR_DIENSTE_VERZEICHNIS_URL = "https://kon-instanz2.titus.ti-dienste.de/connector.sds"; 

        const string CLIENT_ID = "gematikTestPs"; //client_id des Clients für IDP. Wird bei der Registrierung des PS von der Gematik vergeben. Im Titus-Umfeld 'fix'
        
        //Konnektor-Context Information für alle Konnektor Webservice-Calls
        const string ClientSystemId4Context = "myPVS";
        const string WorkplaceId4Context = "WP1";
        const string MandantId4Context = "Mandant1";

        /// <summary>
        /// User Agent für alle HTTP Requests zum IDP und ERezept-Server Format im Implementierungsleitfaden gemILF_PS_eRp 1.3 vorgegeben. Im Titus-Umfeld 'frei wählbar'
        /// </summary>
        const string USER_AGENT = "MyProduct/1.0.1 MyHeroCompany/"+CLIENT_ID;  //A_20015-01 - PS
        const string REDIRECT_URI = "http://test-ps.gematik.de/erezept"; //Die für den Client beim Server hinterlegte redirect_uri. Muss dem bei der Registrierung des PS bei der Gematik hinterlegten Wert entsprechen. Im Titus-Umfeld 'frei wählbar'

        /// <summary>
        /// Client-Zertifikat für die Kommunikation mit dem lokalen Konnektor des PS
        /// kann aus Download aus TITUS unter Mandanteninformation heruntergeladen werden
        /// </summary>
        static readonly X509Certificate2 KonnektorCommunikationCert = new(File.ReadAllBytes(@"C:\work\ps_erp_aps_01.p12"), "00"); 

        static void Main() {

            Console.Out.WriteLine("--------------------------------------------------");
            Console.Out.WriteLine("VAUFixed.DemoBspAusGemSpecCrypt-------------------");
            Console.Out.WriteLine("--------------------------------------------------");

            //Beispiel der VAU aus gemSpec_Krypt_V2.19.0.pdf Seite 98 um zu beweisen, das die VAU-Implementierung das richtige macht.
            VAUFixed.DemoBspAusGemSpecCrypt();

            
            Console.Out.WriteLine("--------------------------------------------------");
            Console.Out.WriteLine("TestCreateERezeptInPraxis-------------------------");
            Console.Out.WriteLine("--------------------------------------------------");

            // Beispiel erstellt ein ERezept in der Arztpraxis (unter Nutzung von IDP und VAU)
            TestCreateERezeptInPraxis();


            Console.Out.WriteLine("--------------------------------------------------");
            Console.Out.WriteLine("TestAcceptRezeptInApotheke------------------------");
            Console.Out.WriteLine("--------------------------------------------------");

            // Beispiel lädt ein ERezept in der Apotheke unter Angabe von taskid und accesscode (unter Nutzung von IDP und VAU)
            // Dieses Rezept sollte vor jedem Lauf in Titus unter Rezeptverwaltung neu erzeugt werden, da derzeit jedes ERezept nur genau einmal geladen werden kann. (Sonst gibt es einen Fehler)
            TestAcceptRezeptInApotheke(taskid : "19b56423-201c-11b2-804f-df8a779f13bd", accesscode : "c8a8086dc855bd7fb19630bfaae254b86068eca45131f32382cb6b27d75841ee");
        }

        /// <summary>
        /// Arzt: ERezept erstellen
        /// - erzeugt einen BearerToken vom IDP Server (300s gültig!)
        /// - bildet den ersten $create-Request zum Erezept-Fachdienst um die RezeptID zu erzeugen. Der Request wird über die VAU verschickt
        ///   siehe https://github.com/gematik/api-erp/blob/master/docs/authentisieren.adoc
        /// - der Vorgang wird ein 2. mal wiederholt um zu demonstrieren, wie mit der VAU und nutzerPseudonym ab dem 2. Call umzugehen ist
        /// 
        /// das macht das Bsp nicht:
        /// - auf ähnliche Weise kann dann der mit dem Konnektor signierte FHIR-Datensatz als Rezept angelegt werden
        /// </summary>
        private static void TestCreateERezeptInPraxis() {
            string bearerPraxis = new IdpClient(PS_KONNEKTOR_DIENSTE_VERZEICHNIS_URL, USER_AGENT, IDP_SERVER_URL, CLIENT_ID, REDIRECT_URI, KonnektorCommunikationCert, ClientSystemId4Context, WorkplaceId4Context, MandantId4Context)
                .GetBearerToken(tokenForApothekeWhenMultipleSmcbFound : false);

            //Praxis Rezept erstellen mit VAU
            string nutzerPseudonym = "0";
            for (int i = 0; i < 2; i++) {
                string contentbody = @"

<Parameters xmlns=""http://hl7.org/fhir"">
  <parameter>
    <name value=""workflowType""/>
    <valueCoding>
      <system value=""https://gematik.de/fhir/CodeSystem/Flowtype""/>
      <code value=""160""/>
    </valueCoding>
  </parameter>
</Parameters>


";

                string content = $@"POST /Task/$create HTTP/1.1
Host: {new Uri(EREZEPT_FACHDIENST_URL).Host}
Authorization: Bearer {bearerPraxis}
Content-Type: application/fhir+xml
Accept: application/fhir+xml;charset=utf-8
Content-Length: {Encoding.UTF8.GetBytes(contentbody).Length}

{contentbody}"; //Content-Length die Zeichenanzahl für UTF8 enthalten, weil der Body später als UTF8 kodiert wird 
                var vau = new VAU(USER_AGENT, EREZEPT_FACHDIENST_URL);

                string requestid = VAU.ByteArrayToHexString(vau.GetRandom(16));
                string aeskey = VAU.ByteArrayToHexString(vau.GetRandom(16));
                string p = $"1 {bearerPraxis} {requestid.ToLowerInvariant()} {aeskey.ToLowerInvariant()} {content}";

                Console.Out.WriteLine($"{requestid.ToLowerInvariant()} {aeskey.ToLowerInvariant()}");

                var gesamtoutput = vau.Encrypt(p);

                var client = new HttpClient {
                    BaseAddress = new Uri(EREZEPT_FACHDIENST_URL), Timeout = TimeSpan.FromSeconds(30),
                    DefaultRequestHeaders = {
                        ExpectContinue = false
                    }
                };
                client.DefaultRequestHeaders.UserAgent.ParseAdd(USER_AGENT);
                
                var httpContent = new ByteArrayContent(gesamtoutput) {
                    Headers = {
                        ContentType = MediaTypeHeaderValue.Parse("application/octet-stream"),
                    }
                };
                httpContent.Headers.Add("X-erp-user", "l"); //Leistungserbringer
                httpContent.Headers.Add("X-erp-resource", "Task");

                HttpResponseMessage response = client.PostAsync($"VAU/{nutzerPseudonym}",
                        httpContent)
                    .Result; // Blocking call!    

                if (response.IsSuccessStatusCode) {
                    Console.Out.WriteLine("VAU Request erfolgreich");
                    foreach (var header in response.Headers) {
                        Console.Out.WriteLine($"{header.Key}={string.Join(",", header.Value)}");
                    }
                    var encryptedResponse = response.Content.ReadAsByteArrayAsync().Result;

                    var decrypt = vau.DecryptWithKey(encryptedResponse, VAU.HexStringToByteArray(aeskey));
                    var xml = Encoding.UTF8.GetString(decrypt);

                    Console.Out.WriteLine($"entschlüsselter Response={xml}");

                    if (response.Headers.TryGetValues("userpseudonym", out var values)) {
                        nutzerPseudonym = values.First();
                        nutzerPseudonym = "0"; //HACK unterschiedl. userpseudonyme gehen mit Titus noch nicht - wird demnächst behoben - TITUS BUG 
                    }
                } else {
                    Console.WriteLine($"{(int) response.StatusCode} ({response.ReasonPhrase})");
                    Console.Out.WriteLine($"Response body: {response.Content.ReadAsStringAsync().Result}");
                }
            }
        }

        /// <summary>
        /// Apotheke: Rezept abrufen
        /// - erzeugt einen BearerToken vom IDP Server (300s gültig!)
        /// - bildet den $accept-Request zum ERezept-Fachdienst um ein ERezept abzurufen und auszugeben. Der Request wird über die VAU verschickt
        ///   siehe https://github.com/gematik/api-erp/blob/master/docs/authentisieren.adoc
        /// </summary>
        /// <param name="taskid"></param>
        /// <param name="accesscode"></param>
        private static void TestAcceptRezeptInApotheke(string taskid, string accesscode) {
            {
                var sw = Stopwatch.StartNew();
                string bearer = new IdpClient(PS_KONNEKTOR_DIENSTE_VERZEICHNIS_URL, USER_AGENT, IDP_SERVER_URL, CLIENT_ID, REDIRECT_URI, KonnektorCommunikationCert, ClientSystemId4Context, WorkplaceId4Context, MandantId4Context)
                    .GetBearerToken(tokenForApothekeWhenMultipleSmcbFound : true);
                Console.Out.WriteLine($"Get Bearer-Token ({sw.ElapsedMilliseconds}ms) = " + bearer);

                string content = $@"POST /Task/{taskid}/$accept?ac={accesscode} HTTP/1.1
Host: {new Uri(EREZEPT_FACHDIENST_URL).Host}
Authorization: Bearer {bearer}
Content-Type: application/fhir+xml
Accept: application/fhir+xml;charset=utf-8

";

                var vau = new VAU(USER_AGENT, EREZEPT_FACHDIENST_URL);

                string requestid = VAU.ByteArrayToHexString(vau.GetRandom(16));
                string aeskey = VAU.ByteArrayToHexString(vau.GetRandom(16));
                string p = $"1 {bearer} {requestid.ToLowerInvariant()} {aeskey.ToLowerInvariant()} {content}";

                Console.Out.WriteLine($"{requestid.ToLowerInvariant()} {aeskey.ToLowerInvariant()}");

                var gesamtoutput = vau.Encrypt(p);

                var client = new HttpClient {
                    BaseAddress = new Uri(EREZEPT_FACHDIENST_URL), Timeout = TimeSpan.FromSeconds(30),
                    DefaultRequestHeaders = {
                        ExpectContinue = false
                    }
                };
                client.DefaultRequestHeaders.UserAgent.ParseAdd(USER_AGENT);

                var httpContent = new ByteArrayContent(gesamtoutput) {Headers = {
                    ContentType = MediaTypeHeaderValue.Parse("application/octet-stream"),
                }};
                httpContent.Headers.Add("X-erp-user", "l"); //Leistungserbringer
                httpContent.Headers.Add("X-erp-resource", "Task");


                HttpResponseMessage response = client.PostAsync("VAU/0", httpContent)
                    .Result; // Blocking call!    

                if (response.IsSuccessStatusCode) {
                    Console.Out.WriteLine("VAU Request erfolgreich");
                    foreach (var header in response.Headers) {
                        Console.Out.WriteLine($"{header.Key}={string.Join(",", header.Value)}");
                    }
                    var encryptedResponse = response.Content.ReadAsByteArrayAsync().Result;

                    var decrypt = vau.DecryptWithKey(encryptedResponse, VAU.HexStringToByteArray(aeskey));
                    var xml = Encoding.UTF8.GetString(decrypt);

                    Console.Out.WriteLine($"entschlüsselter Response={xml}");
                } else {
                    Console.WriteLine($"{(int) response.StatusCode} ({response.ReasonPhrase})");
                    Console.Out.WriteLine($"Response body: {response.Content.ReadAsStringAsync().Result}");
                }
            }
        }
    }
}