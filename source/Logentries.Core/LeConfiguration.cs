namespace Logentries.Core
{
    using System;
    using System.Configuration;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.RegularExpressions;

    using Microsoft.WindowsAzure;

    public class LeConfiguration
    {
        public const string DefaultAddress = "api.logentries.com";

        public const int DefaultPort = 10000;

        public const int DefaultSslPort = 20000;

        public static readonly X509Certificate2 DefaultSslCertificate =
            new X509Certificate2(Encoding.UTF8.GetBytes(
@"-----BEGIN CERTIFICATE-----
MIIFSjCCBDKgAwIBAgIDCQpNMA0GCSqGSIb3DQEBBQUAMGExCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR0wGwYDVQQLExREb21haW4gVmFsaWRh
dGVkIFNTTDEbMBkGA1UEAxMSR2VvVHJ1c3QgRFYgU1NMIENBMB4XDTE0MDQxNTEz
NTcxNVoXDTE2MDkxMzA0MTMzMFowgcExKTAnBgNVBAUTIEhpL1RHbXlmUEpJYTFy
b0NQdlJ1U1NNRVdLOFp0NUtmMRMwEQYDVQQLEwpHVDAzOTM4NjcwMTEwLwYDVQQL
EyhTZWUgd3d3Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvY3BzIChjKTEyMS8wLQYD
VQQLEyZEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQgLSBRdWlja1NTTChSKTEbMBkG
A1UEAxMSYXBpLmxvZ2VudHJpZXMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAwGsgjVb/pn7Go1jqNQVFsN+VEMRFpu7bJ5i+Lv/gY9zXBDGULr3d
j9/hB/pa49nLUpy9GsaFru2AjNoveoVoe5ng2QhZRlUn77hxkoZsaiD+rrH/D/Yp
LP3b/pNQg+nNTC81uwbhlxjIoeMSaPGjr1SFjZ1StCprZKFRu3IV+2/wZ+STUz/L
aA3r6J86DRptasbzYMkDyWlUzN3nhYUcPUNrd4jSk+soSDEuDpHMahgRdQBo6Dht
EKCSY+vB5ZIgEydI7mra8ygRjXotvc0zeb8Jvo8ZhyLDwvxjgo9F6Li3h/tfAjRR
4ngV7yg9o8MgXN852GMHpUxzqhygLeyqSQIDAQABo4IBqDCCAaQwHwYDVR0jBBgw
FoAUjPTZkwpHvACgSs5LdW6gtrCyfvwwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW
MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUghJhcGkubG9nZW50cmll
cy5jb20wQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2d0c3NsZHYtY3JsLmdlb3Ry
dXN0LmNvbS9jcmxzL2d0c3NsZHYuY3JsMB0GA1UdDgQWBBRowYR/aaGeiRRQxbaV
1PI8hS4m9jAMBgNVHRMBAf8EAjAAMHUGCCsGAQUFBwEBBGkwZzAsBggrBgEFBQcw
AYYgaHR0cDovL2d0c3NsZHYtb2NzcC5nZW90cnVzdC5jb20wNwYIKwYBBQUHMAKG
K2h0dHA6Ly9ndHNzbGR2LWFpYS5nZW90cnVzdC5jb20vZ3Rzc2xkdi5jcnQwTAYD
VR0gBEUwQzBBBgpghkgBhvhFAQc2MDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cu
Z2VvdHJ1c3QuY29tL3Jlc291cmNlcy9jcHMwDQYJKoZIhvcNAQEFBQADggEBAAzx
g9JKztRmpItki8XQoGHEbopDIDMmn4Q7s9k7L9nT5gn5XCXdIHnsSe8+/2N7tW4E
iHEEWC5G6Q16FdXBwKjW2LrBKaP7FCRcqXJSI+cfiuk0uywkGBTXpqBVClQRzypd
9vZONyFFlLGUwUC1DFVxe7T77Dv+pOPuJ7qSfcVUnVtzpLMMWJsDG6NHpy0JhsS9
wVYQgpYWRRZ7bJyfRCJxzIdYF3qy/P9NWyZSlDUuv11s1GSFO2pNd34p59GacVAL
BJE6y5eOPTSbtkmBW/ukaVYdI5NLXNer3IaK3fetV3LvYGOaX8hR45FI1pvyKYvf
S5ol3bQmY1mv78XKkOk=
-----END CERTIFICATE-----"));

        // Restricted symbols that should not appear in host name.
        // See http://support.microsoft.com/kb/228275/en-us for details.
        private static readonly Regex ForbiddenHostNameChars = new Regex(@"[/\\\[\]\""\:\;\|\<\>\+\=\,\?\* _]{1,}", RegexOptions.Compiled);

        private static readonly string[] TokenConfigKeys = { "Logentries.Token", "LOGENTRIES_TOKEN" };

        public static Guid GetValidToken(string token)
        {
            Guid result;

            if (Guid.TryParse(token, out result))
            {
                return result;
            }

            foreach (var keyName in TokenConfigKeys)
            {
                token = RetrieveSetting(keyName);
                if (Guid.TryParse(token, out result))
                {
                    return result;
                }
            }

            throw new ConfigurationErrorsException("Your Logentries token value is invalid or missing");
        }

        public static string GetValidHostName(string hostName)
        {
            if (IsValidHostName(hostName))
            {
                return hostName;
            }

            try
            {
                return Environment.MachineName;
            }
            catch (InvalidOperationException)
            {
                return string.Empty;
            }
        }

        private static string RetrieveSetting(string name)
        {
            var value = CloudConfigurationManager.GetSetting(name);

            if (string.IsNullOrWhiteSpace(value))
            {
                try
                {
                    value = Environment.GetEnvironmentVariable(name);
                }
                catch (SecurityException)
                {
                }
            }

            return value;
        }

        private static bool IsValidHostName(string hostName)
        {
            return !string.IsNullOrWhiteSpace(hostName) && !ForbiddenHostNameChars.IsMatch(hostName);
        }
    }
}
