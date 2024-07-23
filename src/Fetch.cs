using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Sharphound
{
    public class Fetch
    {
        public static ManagementScope NewWmiConnection(string server, string wmiNamespace)
        {
            ConnectionOptions connection = new ConnectionOptions();
            ManagementScope wmiConnection = null;

            try
            {
                if (!string.IsNullOrEmpty(wmiNamespace))
                {
                    wmiConnection = new ManagementScope(wmiNamespace, connection);
                    Console.WriteLine($"[+] Connecting to {wmiConnection.Path}");
                    wmiConnection.Connect();
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[!] Access to the WMI provider was not authorized: {ex.Message.Trim()}");
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"[!] Could not connect to {wmiNamespace}: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unhandled exception of type {ex.GetType()} occurred: {ex.Message}");
            }
            return wmiConnection;
        }

        public static int InitiateSccmClientOperationExMethodCall(string query, string smsProvider, string collectionId, string deviceId, string siteCode)
        {
            try
            {
                // Get the SMS_ClientOperation WMI class
                ManagementScope scope = NewWmiConnection(smsProvider, @$"root\SMS\site_{siteCode}");
                ManagementClass clientOperationClass = new ManagementClass(scope, new ManagementPath("SMS_ClientOperation"), null);

                //Prepare the content of the Param Parameter for the method call
                var queryPlainTextBytes = Encoding.UTF8.GetBytes(query);
                string queryBase64 = Convert.ToBase64String(queryPlainTextBytes);
                string parametersXML = $"<ScriptParameters><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"kustoquery\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:RSgwKQ==\"/><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"select\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:RGV2aWNlOkRldmljZSxMaW5lOk51bWJlcixDb250ZW50OlN0cmluZw==\"/><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"wmiquery\" GroupClass=\"\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:{queryBase64}\"/></ScriptParameters>";
                SHA256 SHA256 = new SHA256Cng();
                byte[] parametersBytes = SHA256.ComputeHash(Encoding.Unicode.GetBytes(parametersXML));
                string parametersHash = string.Join("", parametersBytes.Select(b => b.ToString("X2"))).ToLower();
                string contentXml = "" +
                            "<ScriptContent ScriptGuid='7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14'>" +
                                "<ScriptVersion>1</ScriptVersion>" +
                                "<ScriptType>0</ScriptType>" +
                                "<ScriptHash ScriptHashAlg='SHA256'>e77a6861a7f6fc25753bc9d7ab49c26d2ddfc426f025b902acefc406ae3b3732</ScriptHash>" +
                                "<ScriptParameters>" +
                                    "<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='kustoquery' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:RSgwKQ=='/>" +
                                    "<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='select' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:RGV2aWNlOkRldmljZSxMaW5lOk51bWJlcixDb250ZW50OlN0cmluZw=='/>" +
                                    $"<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='wmiquery' GroupClass='' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:{queryBase64}'/>" +
                                "</ScriptParameters>" +
                                $"<ParameterGroupHash ParameterHashAlg='SHA256'>{parametersHash}</ParameterGroupHash>" +
                            "</ScriptContent>";

                byte[] contentPlainTextBytes = Encoding.UTF8.GetBytes(contentXml);
                string contentBase64 = Convert.ToBase64String(contentPlainTextBytes);

                // Set up the rest of the input parameters for the method call
                ManagementBaseObject inParams = clientOperationClass.GetMethodParameters("InitiateClientOperationEx");
                inParams["Type"] = (uint)145;
                inParams["TargetCollectionID"] = collectionId;
                uint.TryParse(deviceId, out uint devId);
                inParams["TargetResourceIDs"] = new uint[] { devId };
                inParams["RandomizationWindow"] = null;
                inParams["Param"] = contentBase64;

                // Call the InitiateClientOperationEx method with the specified arguments
                ManagementBaseObject outParams = clientOperationClass.InvokeMethod("InitiateClientOperationEx", inParams, null);
                int operationId = Convert.ToInt32(outParams.Properties["OperationID"].Value);
                if (operationId > 0)
                {
                    Console.WriteLine("[+] Fallback method call succeeded");
                }
                else
                {
                    Console.WriteLine("[!] Method call failed with error code {0}.", operationId);
                }
                return operationId;
            }
            catch (ManagementException ex)
            {
                Console.WriteLine("[!] An error occurred while attempting to call the SMS Provider: " + ex.Message);
                return 0;
            }
        }

        public static int GetSccmOperationIdForQuery(string smsProvider, string siteCode, string collectionId, string fetchResultsFile)
        {
            int operationId = 0;

            // Trust self-signed certificates on SMS Providers
            var trustAllCerts = new TrustAllCertsPolicy();
            ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;

            // Prepare query
            string fetchResultsFileFormatted = fetchResultsFile.Replace(@"\", @"\\");
            string query = $"FileContent('{fetchResultsFileFormatted}')";
            string json = $"{{\"InputQuery\":\"{query}\"}}";
            byte[] data = Encoding.UTF8.GetBytes(json);

            // Prepare request to AdminService
            string url = $"https://{smsProvider}/AdminService/v1.0/Collections('{collectionId}')/AdminService.RunCMPivot";
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.UseDefaultCredentials = true;

            try
            {
                HttpWebResponse response = null;
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                Console.WriteLine($"[+] Sending CMPivot query to AdminService for contents of {fetchResultsFile} on clients in collection {collectionId}");
                using (response = (HttpWebResponse)request.GetResponse())
                {
                    var statusCode = response.StatusCode;
                    using (var streamReader = new StreamReader(response.GetResponseStream()))
                    {
                        var jsonResponse = streamReader.ReadToEnd();
                        var jsonObject = JsonConvert.DeserializeObject<JObject>(jsonResponse);
                        var regex = new Regex("\"OperationId\":\\s*\\d+");
                        var match = regex.Match(jsonObject.ToString());

                        if (match.Success)
                        {
                            operationId = int.Parse(Regex.Match(match.Value, "\\d+").Value);
                            Console.WriteLine($"[+] Found OperationId for CMPivot query: {operationId}");
                        }
                        else
                        {
                            Console.WriteLine("[!] Could not find an OperationId in the response");
                        }
                    }
                    return operationId;
                }
            }

            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    switch (response.StatusCode)
                    {
                        case HttpStatusCode.BadRequest:
                            //Handle 400 Error and fall back to SMS Provider method call to insure query is valid
                            query = !string.IsNullOrEmpty(query) ? query.Replace(@"\", @"\\") : null;
                            Console.WriteLine("[!] Received a 400 ('Bad request') response from the API. Falling back to SMS Provider WMI method ");
                            operationId = InitiateSccmClientOperationExMethodCall(query, smsProvider, collectionId, fetchResultsFile, siteCode);
                            if (operationId != 0)
                            {
                                return operationId;
                            }
                            Console.WriteLine($"[!] The AdminService call failed due to an invalid query: {query}");
                            break;
                        case HttpStatusCode.NotFound:
                            // Handle HTTP 404 error
                            Console.WriteLine($"[!] Could not find a URI for a resource matching: {collectionId}");
                            break;
                        case HttpStatusCode.InternalServerError:
                            // Handle HTTP 500 error
                            Console.WriteLine($"[!] The requested AdminService endpoint responded with a 500 internal server error");
                            break;
                        default:
                            // Handle other HTTP errors
                            Console.WriteLine($"[!] The AdminService responded with an error message: {ex.Message}\r\n");
                            Console.WriteLine($"{ex.InnerException}\r\n");
                            Console.WriteLine($"{ex.StackTrace}");
                            break;
                    }
                }

                else if (ex.Status == WebExceptionStatus.NameResolutionFailure)
                {
                    // Handle DNS resolution failure error
                    Console.WriteLine($"[!] The SMS Provider name could not be resolved: {smsProvider}");
                }
                return operationId;
            }
        }

        public static List<JObject> PrepareCMPivotQueryResults(JObject cmPivotResponse)
        {
            List<JObject> cmPivotResults = new List<JObject>();

            // Extract the "Content" property for each "Line"
            var queryResults = cmPivotResponse["value"]
                .SelectMany(lineValue => lineValue["Result"])
                .Select(lineResult => new
                {
                    Line = (string)lineResult["Line"],
                    Content = (string)lineResult["Content"],
                    Device = (string)lineResult["Device"]
                })
                .ToList();

            foreach (var lineData in queryResults)
            {
                // Parse the "Content" property value for each "Line" as a JObject
                JObject hostContent = JObject.Parse(lineData.Content);

                // Update the "version" attribute in the "meta" object to 5
                Console.WriteLine($"[*] Setting meta version");
                if (hostContent["meta"] is JObject metaObject)
                {
                    metaObject["version"] = 5;
                }
                cmPivotResults.Add(hostContent);
            }
            return cmPivotResults;
        }

        public static async Task<List<JObject>> GetFetchResultsFromShare(string remoteDirectory, int lookbackDays)
        {
            List<JObject> fetchResults = new List<JObject>();
            try
            {
                if (Directory.Exists(remoteDirectory))
                {
                    foreach (string dir in Directory.EnumerateDirectories(remoteDirectory))
                    {
                        string dirName = new DirectoryInfo(dir).Name;

                        // Parse directory name into date
                        if (DateTime.TryParseExact(dirName, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime dirDate))
                        {
                            // Check if this date is within the lookback period
                            if (dirDate >= DateTime.Today.AddDays(-lookbackDays))
                            {
                                // Enumerate JSON files in this directory
                                foreach (string filePath in Directory.EnumerateFiles(dir, "*.json"))
                                {
                                    // Read and deserialize JSON file
                                    using (StreamReader sr = new StreamReader(filePath))
                                    {
                                        string jsonText = await sr.ReadToEndAsync();
                                        JObject jsonObj = JObject.Parse(jsonText);
                                        fetchResults.Add(jsonObj);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[!] Directory does not exist.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An error occurred: {ex.Message}");
            }
            return fetchResults;
        }

        public static async Task<JObject> QuerySccmAdminService(string smsProvider, string siteCode, string collectionId, string fetchResultsFile, int fetchTimeout)
        {
            int operationId = GetSccmOperationIdForQuery(smsProvider, siteCode, collectionId, fetchResultsFile);

            if (operationId != 0)
            {
                int attemptCounter = 1;
                int maxAttempts = 0;
                if (fetchTimeout > 0)
                {
                    // User supplied timeout from minutes to seconds with 1 request every 10 seconds
                    maxAttempts = fetchTimeout * 60 / 10;
                }
                int status = 0;
                string url = $"https://{smsProvider}/AdminService/v1.0/Collections('{collectionId}')/AdminService.CMPivotResult(OperationId={operationId})";

                // Trust self-signed certificates on SMS Providers
                var clientHandler = new HttpClientHandler();
                clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
                clientHandler.UseDefaultCredentials = true;

                var client = new HttpClient(clientHandler);
                HttpResponseMessage response = null;
                Console.WriteLine($"[+] Querying for CMPivot operation results at {url}");

                // Loop infinitely or until the provided timeout is reached, checking for results every 10 seconds
                while (attemptCounter <= maxAttempts || fetchTimeout == 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                    Console.WriteLine($"[+] Checking whether CMPivot has finished querying clients: attempt {attemptCounter} of {(maxAttempts > 0 ? maxAttempts : "∞")}");
                    response = await client.GetAsync(url);
                    status = (int)response.StatusCode;

                    if (status != 200)
                    {
                        attemptCounter++;
                        Console.WriteLine("[+] Trying again in 10 seconds");
                    }
                    else
                    {
                        Console.WriteLine("[+] Successfully retrieved CMPivot results from AdminService");
                        break;
                    }
                }

                if (status == 200)
                {
                    // Deserialize the received JSON
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var jsonBody = responseBody.Replace("\\r\\n\\r\\n", Environment.NewLine);
                    var jsonObject = JsonConvert.DeserializeObject<JObject>(jsonBody);

                    // Here we display the output as JSON after the user supplies the required flag
                    Console.WriteLine(jsonObject.ToString());
                    return jsonObject;
                }
                else if (status == 404)
                {
                    Console.WriteLine("[!] Could not collect FETCH results before FetchTimeout was reached");
                    Console.WriteLine("[+] This could mean that the device is not online or the timeout value is too short");
                    Console.WriteLine($"[+] When they are ready, the results can be retrieved manually from {url}");
                }
            }
            else
            {
                Console.WriteLine("[!] Could not successfully create an operation via the AdminService API");
            }
            return null;
        }

        public static async Task<List<JObject>> QuerySiteDatabase(string siteDatabaseFqdn, string siteCode)
        {
            string connectionString = $"Server={siteDatabaseFqdn};Database=CM_{siteCode};Integrated Security=True;";

            // Get most recent collection for each MachineID
            string query = @"
            WITH LatestCollections AS (
                SELECT 
                    MachineID,
                    CollectionDatetime00,
                    Output00,
                    ROW_NUMBER() OVER (PARTITION BY MachineID ORDER BY CollectionDatetime00 DESC) as RowNum
                FROM SpecterOps_BloodHound_Data_DATA
            )
            SELECT 
                LC.MachineID,
                LC.CollectionDatetime00,
                LC.Output00,
                SD.SID0,
                SD.Netbios_Name0,
                SD.Full_Domain_Name0
            FROM LatestCollections LC
            LEFT JOIN System_DISC SD ON LC.MachineID = SD.ItemKey
            WHERE LC.RowNum = 1
            ORDER BY LC.CollectionDatetime00 DESC";

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                try
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            var results = new List<JObject>();

                            while (await reader.ReadAsync())
                            {
                                string computerSid = reader.GetString(3);
                                string computerFqdn = reader.GetString(4) + "." + reader.GetString(5);

                                // Get Output00 for this machine and add to the list of objects to ingest
                                string output = reader.GetString(2);

                                // Remove escaping for double quotes (e.g., \")
                                var jsonBody = output.Replace("\\\"", "\"");
                                var jsonObject = JsonConvert.DeserializeObject<JObject>(jsonBody);
                                results.Add(jsonObject);
                            }

                            if (results.Count > 0)
                            {
                                Console.WriteLine($"Fetched {results.Count} records.");
                                return results;
                            }
                            else
                            {
                                Console.WriteLine("No data found in the table.");
                            }
                        }
                    }
                }
                catch (SqlException ex)
                {
                    Console.WriteLine($"SQL Error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            return null;
        }

        public class TrustAllCertsPolicy
        {
            public bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                return true;
            }
        }
    }
}
