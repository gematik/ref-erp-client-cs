# ref-erp-client-cs

## Motivation

Der Beispiel-Code zeigt exemplarisch die Ansteuerung von IDP und ERezept-Fachdienst aus Arzt- und Apothekensystemen in C# mit Hilfe der ***TITUS-Demoumgebung***.<br>
Der Beispielcode versucht viele Aspekte der Spezifikation umzusetzen ist aber nicht geeignet 1:1 in einer Produktivumgebung eingesetzt zu werden, weil vor allem 
Robustheit und Fehlertolleranz nicht ausreichend umgesetzt sind.

## Funktionsumfang

- Beispiel der VAU aus gemSpec_Krypt_V2.19.0.pdf Seite 98 um zu beweisen, das die VAU-Implementierung das richtige macht.

- Arzt: ERezept erstellen
  - `TestCreateERezeptInPraxis();`
  - erzeugt einen BearerToken vom IDP Server (300s gültig!)
  - bildet den ersten $create-Request zum Erezept-Fachdienst um die RezeptID zu erzeugen. Der Request wird über die VAU verschickt
    siehe https://github.com/gematik/api-erp/blob/master/docs/authentisieren.adoc
  - der Vorgang wird ein 2. mal wiederholt um zu demonstrieren, wie mit der VAU und nutzerPseudonym ab dem 2. Call umzugehen ist
  - das macht das Bsp **nicht**: 
    - auf ähnliche Weise kann dann der mit dem Konnektor signierte FHIR-Datensatz als Rezept angelegt werden.

- Apotheke: E-Rezept abholen
  - Beispiel lädt ein ERezept in die Apotheke unter Angabe von taskid und accesscode (unter Nutzung von IDP und VAU).<br>
    `TestAcceptRezeptInApotheke(taskid : "19b56423-201c-11b2-804f-df8a779f13bd", accesscode : "c8a8086dc855bd7fb19630bfaae254b86068eca45131f32382cb6b27d75841ee");`<br>
    Dieses Rezept sollte vor jedem Lauf in Titus unter Rezeptverwaltung neu erzeugt werden, da derzeit jedes ERezept nur genau einmal geladen werden kann. (Sonst gibt es einen Fehler)
  - erzeugt einen BearerToken vom IDP Server (300s gültig!)
  - bildet den $accept-Request zum ERezept-Fachdienst um ein ERezept abzurufen und auszugeben. 
  - Der Request wird über die VAU verschickt
        siehe https://github.com/gematik/api-erp/blob/master/docs/authentisieren.adoc

**Derzeit sind im Code noch einige Stellen mit `TITUS BUG` markiert, die in den nächsten TITUS-Releases behoben werden und dann in diesem Projekt korrigiert werden können**

## Konfiguration

In `Program.cs` sind alle URLs, und variablen Einstellungsparameter für den Konnektorkontext, IDP als Konstanten angelegt und so konfiguriert, dass man nur 
einen Parmameter zwingend anpassen muss: <br>

	/// Client-Zertifikat für die Kommunikation mit dem lokalen Konnektor des PS
	/// kann aus Download aus TITUS unter Mandanteninformation heruntergeladen werden
	static readonly X509Certificate2 KonnektorCommunikationCert = new(File.ReadAllBytes(@"C:\work\ps_erp_aps_01.p12"), "00");

**Ersetzen Sie `C:\work\ps_erp_aps_01.p12` durch das Client-Zertifikat aus Ihrem TITUS-Account!**

## xsds-Ordner
enthält die für die Generierung der Konnektor-Webserviceendpunkt nötigen WDSL Dateien<br>
`VS2029 -> Add Service Reference ...`<br>
Download unter: https://fachportal.gematik.de/fileadmin/Fachportal/Downloadcenter/Schemata-_und_WSDL-Dateien/Schema-_und_WSDL-Dateien/OPB3.1_Schemadateien_R3.1.2_Kon_PTV3_20191002.zip
