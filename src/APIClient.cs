using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Sharphound
{
    public class APIClient
    {
        private HttpClient _httpClient;
        private string _scheme;
        private string _host;
        private int _port;
        private Credentials _credentials;
        private string _userAgent;

        public APIClient(HttpClient httpClient, string scheme, string host, int port, Credentials credentials, string userAgent = @"sharphound/2.1.9.0")
        {
            _httpClient = httpClient;
            _scheme = scheme;
            _host = host;
            _port = port;
            _credentials = credentials;
            _userAgent = userAgent;
        }

        private string FormatUrl(string uri)
        {
            string formattedUri = uri;
            if (uri.StartsWith("/"))
            {
                formattedUri = formattedUri.Substring(1);
            }

            return $"{_scheme}://{_host}:{_port}/{formattedUri}";
        }

        private Task<HttpRequestMessage> CreateRequestMessageAsync(string method, string uri, byte[] body = null)
        {
            var request = new HttpRequestMessage(new HttpMethod(method), FormatUrl(uri));

            if (body != null)
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }

            request.Headers.Add("User-Agent", _userAgent);

            /*
            // Sign our request
            var digester = new HMACSHA256(Encoding.UTF8.GetBytes(_credentials.TokenKey));
            var content = Encoding.UTF8.GetBytes($"{request.Method}{request.RequestUri.AbsolutePath}");
            var opKey = digester.ComputeHash(content);
            digester = new HMACSHA256(opKey);
            var dateKey = digester.ComputeHash(Encoding.UTF8.GetBytes(formattedDate.Substring(0, 13)));
            var bodyBytes = request.Content == null ? new byte[0] : await request.Content.ReadAsByteArrayAsync();
            digester = new HMACSHA256(dateKey);
            var finalSignature = digester.ComputeHash(bodyBytes);
            request.Headers.Add("Signature", Convert.ToBase64String(finalSignature));
            */
            return Task.FromResult(request);
        }

        private async Task<HttpResponseMessage> SendRequestAsync(HttpRequestMessage request)
        {
            return await _httpClient.SendAsync(request);
        }

        public async Task<JObject> CreateClientAsync(string name, string type = "sharphound", string domainController = "")
        {
            var data = new
            {
                name,
                type,
                domain_controller = domainController
            };

            var body = JsonConvert.SerializeObject(data);
            var request = CreateRequestMessageAsync("POST", "/api/v2/clients", Encoding.UTF8.GetBytes(body));

            var response = await SendRequestAsync(await request);
            var responseContent = await response.Content.ReadAsStringAsync();
            return JObject.Parse(responseContent);
        }

        public async Task<HttpResponseMessage> CreateJobAsync(string clientId, bool adStructureCollection = false, bool allTrustedDomains = false,
            string[] domains = default, bool localGroupCollection = false, string[] ous = default, bool sessionCollection = false)
        {
            var data = new
            {
                ad_structure_collection = adStructureCollection,
                all_trusted_domains = allTrustedDomains,
                domains,
                local_group_collection = localGroupCollection,
                ous,
                session_collection = sessionCollection
            };

            var body = JsonConvert.SerializeObject(data);
            var request = CreateRequestMessageAsync("POST", $"/api/v2/clients/{clientId}/jobs", Encoding.UTF8.GetBytes(body));

            return await SendRequestAsync(await request);
        }

        public async Task<HttpResponseMessage> EndJobAsync()
        {
            var data = new
            {
                status = "Complete",
                message = "Manual ingest upload"
            };

            var body = JsonConvert.SerializeObject(data);
            var request = CreateRequestMessageAsync("POST", "/api/v2/jobs/end", Encoding.UTF8.GetBytes(body));

            return await SendRequestAsync(await request);
        }

        public async Task<JObject> GetClientsAsync()
        {
            var request = CreateRequestMessageAsync("GET", "/api/v2/clients");

            var response = await SendRequestAsync(await request);
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseContent);
            return JObject.Parse(responseContent);
        }

        public async Task<JObject> GetNewClientTokenAsync(string clientId)
        {
            var request = CreateRequestMessageAsync("PUT", $"/api/v2/clients/{clientId}/token");

            var response = await SendRequestAsync(await request);
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseContent);
            return JObject.Parse(responseContent);
        }

        public async Task<JArray> GetJobsAsync()
        {
            var request = CreateRequestMessageAsync("GET", "/api/v2/jobs/available");

            var response = await SendRequestAsync(await request);
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseContent);
            return (JArray)JObject.Parse(responseContent)["data"];
        }

        public async Task<HttpResponseMessage> PostIngestAsync(byte[] body)
        {
            var request = CreateRequestMessageAsync("POST", "/api/v2/ingest", body);

            return await SendRequestAsync(await request);
        }

        public async Task<HttpResponseMessage> StartJobAsync(int jobId)
        {
            var data = new
            {
                id = jobId
            };

            var body = JsonConvert.SerializeObject(data);
            var request = CreateRequestMessageAsync("POST", "/api/v2/jobs/start", Encoding.UTF8.GetBytes(body));

            return await SendRequestAsync(await request);
        }
    }

    public class Credentials
    {
        public string TokenId { get; }
        public string TokenKey { get; }

        public Credentials(string tokenId, string tokenKey)
        {
            TokenId = tokenId;
            TokenKey = tokenKey;
        }
    }

    public class APIIngest
    {
        private static async Task SplitFile(string fileName, string folderResized, int objectLimit)
        {
            Console.WriteLine($"[*] Loading {fileName}");
            using (StreamReader file = File.OpenText(fileName))
            using (JsonTextReader reader = new JsonTextReader(file))
            {
                JObject data = (JObject)await JToken.ReadFromAsync(reader);
                int totalObjects = data["meta"]["count"].Value<int>();
                Console.WriteLine($"[*] Total Objects: {totalObjects}");
                int objectCount = 0;
                int fileCount = 0;

                while (objectCount < totalObjects)
                {
                    JObject splitData = new JObject();
                    JArray dataArray = new JArray();
                    int remainingObjects = totalObjects - objectCount;
                    int objectsToTake = Math.Min(objectLimit, remainingObjects);

                    for (int i = 0; i < objectsToTake; i++)
                    {
                        dataArray.Add(data["data"][objectCount + i]);
                    }

                    objectCount += objectsToTake;

                    splitData["data"] = dataArray;
                    splitData["meta"] = data["meta"];
                    splitData["meta"]["count"] = objectCount;

                    string[] fileNameSplit = fileName.Split(Path.DirectorySeparatorChar);
                    string fileOutName = $"{fileNameSplit[fileNameSplit.Length - 1].Split('.')[0]}_{fileCount}.{fileNameSplit[fileNameSplit.Length - 1].Split('.')[1]}";
                    string fileOutFullName = Path.Combine(folderResized, fileOutName);

                    Console.WriteLine($"[*] Writing {fileOutFullName} - {objectCount} of {totalObjects}");
                    File.WriteAllText(fileOutFullName, splitData.ToString(Formatting.None));
                    fileCount++;
                }
            }
        }


        private static void RemoveBOM(string fileName)
        {
            Console.WriteLine($"[*] Converting from utf-8-sig to utf-8: {fileName}");
            string fileContent = File.ReadAllText(fileName, Encoding.UTF8);
            File.WriteAllText(fileName, fileContent, Encoding.UTF8);
        }

        private static void SetMetaVersion(string fileName, int version)
        {
            Console.WriteLine($"[*] Setting meta version: {fileName}");
            JObject data = JObject.Parse(File.ReadAllText(fileName));
            data["meta"]["version"] = version;
            File.WriteAllText(fileName, data.ToString(Formatting.None));
        }

        public static async Task IngestDataFromFolder(APIClient adminClient, Credentials adminCredentials, string ingestClientName, string userAgent, string jsonFilesFolder, string BHE_DOMAIN, string SCHEME, int PORT)
        {
            // Check if ingest client specified in env already exists
            JToken ingestClient = null;
            Console.WriteLine("[*] Checking if ingest client " + ingestClientName + " exists");
            JObject getApiClientsResponse = await adminClient.GetClientsAsync();
            JArray apiClients = (JArray)getApiClientsResponse["data"];

            foreach (JObject apiClient in apiClients)
            {
                if (apiClient["name"] != null && apiClient["name"].ToString() == ingestClientName)
                {
                    ingestClient = apiClient;
                    break;
                }
            }

            if (ingestClient != null)
            {
                Console.WriteLine("[*] Ingest client named " + ingestClientName + " found!");

                // Generate new API token
                Console.WriteLine("[*] Generating new API token for ingest client");
                JObject newToken = await adminClient.GetNewClientTokenAsync(ingestClient["id"].ToString());
                ingestClient["token"] = newToken;
            }
            else
            {
                Console.WriteLine("[*] Ingest client named " + ingestClientName + " not found");

                // Create ingest client
                Console.WriteLine("[*] Creating ingest client: " + ingestClientName);
                string clientType = "sharphound";
                JObject createdClient = await adminClient.CreateClientAsync(ingestClientName, clientType);
                ingestClient = createdClient["data"] as JObject;
            }

            // Create job for ingest client
            Console.WriteLine("[*] Creating job for client");
            JObject jobData = new JObject();
            jobData["ad_structure_collection"] = true;
            jobData["local_group_collection"] = true;
            jobData["session_collection"] = true;

            HttpResponseMessage response = await adminClient.CreateJobAsync(ingestClient["id"].ToString(), jobData.Value<bool>("ad_structure_collection"),
                jobData.Value<bool>("all_trusted_domains"), jobData["domains"]?.ToObject<string[]>(), jobData.Value<bool>("local_group_collection"),
                jobData["ous"]?.ToObject<string[]>(), jobData.Value<bool>("session_collection"));
            Console.WriteLine($"[*] Response: {response}");

            
            // Create ingest BHE client
            Credentials ingestCredentials = new Credentials(ingestClient["token"]["data"]["id"].ToString(), ingestClient["token"]["data"]["key"].ToString());

            // Proxy settings
            var httpHandler = new HttpClientHandler();
            //var trustAllCerts = new TrustAllCertsPolicy();
            //ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;
            //httpHandler.Proxy = new WebProxy("http://127.0.0.1:8080");

            // Signer
            var authHandler = new AuthSigner(ingestCredentials.TokenKey, ingestCredentials.TokenId, httpHandler);
            var client = new HttpClient(authHandler);
            APIClient signedIngestClient = new APIClient(client, SCHEME, BHE_DOMAIN, PORT, ingestCredentials, userAgent);
            
            // Get jobs
            Console.WriteLine("[*] Get jobs for client");
            JArray jobs = await signedIngestClient.GetJobsAsync();
            if (jobs.Count == 0)
            {
                Console.WriteLine("[!] No jobs. Schedule an on-demand scan for client and run the script again.");
                return;
            }

            // Tell BHE we are starting the next job
            JObject nextJob = jobs[0] as JObject;
            Console.WriteLine("[*] Starting next job with ID: " + nextJob["id"]);
            response = await signedIngestClient.StartJobAsync((int)nextJob["id"]);
            Console.WriteLine($"[*] Response: {response}");

            // Iterate files
            foreach (string fileName in Directory.EnumerateFiles(jsonFilesFolder))
            {
                string jsonFile = Path.Combine(jsonFilesFolder, fileName);

                // Load JSON file
                Console.WriteLine($"[*] Ingesting {jsonFile}");
                string jsonContent = File.ReadAllText(jsonFile);
                JObject data = JObject.Parse(jsonContent);

                if (jsonFile.EndsWith("domains_0.json"))
                {
                    // Mark domains as collected
                    JArray domainData = (JArray)data["data"];
                    foreach (JObject domain in domainData)
                    {
                        domain["Properties"]["collected"] = true;
                    }

                    // Fix trust attributes
                    if (jsonFile.EndsWith("domains_0.json"))
                    {
                        foreach (JObject domain in domainData)
                        {
                            JArray trusts = (JArray)domain["Trusts"];
                            foreach (JObject trust in trusts)
                            {
                                string trustDirection;
                                if (TrustDirectionLookup.Values.TryGetValue((int)trust["TrustDirection"], out trustDirection))
                                {
                                    trust["TrustDirection"] = trustDirection;
                                }

                                string trustType;
                                if (TrustTypeLookup.Values.TryGetValue((int)trust["TrustType"], out trustType))
                                {
                                    trust["TrustType"] = trustType;
                                }
                            }
                        }
                    }
                }

                // Ingest data
                response = await signedIngestClient.PostIngestAsync(Encoding.UTF8.GetBytes(data.ToString(Formatting.None)));
                Console.WriteLine($"[*] Response: {response}");
            }

            // Mark job as complete
            Console.WriteLine("[*] Marking job as done");
            response = await signedIngestClient.EndJobAsync();
            Console.WriteLine($"[*] Response: {response}");
        }

        public static async Task IngestDataFromJSON(APIClient adminClient, Credentials adminCredentials, string ingestClientName, string userAgent, JObject jsonToIngest, string BHE_DOMAIN, string SCHEME, int PORT)
        {
            // Check if ingest client specified in env already exists
            JToken ingestClient = null;
            Console.WriteLine("[*] Checking if ingest client " + ingestClientName + " exists");
            JObject getApiClientsResponse = await adminClient.GetClientsAsync();
            JArray apiClients = (JArray)getApiClientsResponse["data"];

            foreach (JObject apiClient in apiClients)
            {
                if (apiClient["name"] != null && apiClient["name"].ToString() == ingestClientName)
                {
                    ingestClient = apiClient;
                    break;
                }
            }

            if (ingestClient != null)
            {
                Console.WriteLine("[*] Ingest client named " + ingestClientName + " found!");

                // Generate new API token
                Console.WriteLine("[*] Generating new API token for ingest client");
                JObject newToken = await adminClient.GetNewClientTokenAsync(ingestClient["id"].ToString());
                ingestClient["token"] = newToken;
            }
            else
            {
                Console.WriteLine("[*] Ingest client named " + ingestClientName + " not found");

                // Create ingest client
                Console.WriteLine("[*] Creating ingest client: " + ingestClientName);
                string clientType = "sharphound";
                JObject createdClient = await adminClient.CreateClientAsync(ingestClientName, clientType);
                ingestClient = createdClient["data"] as JObject;
            }

            // Create job for ingest client
            Console.WriteLine("[*] Creating job for client");
            JObject jobData = new JObject();
            jobData["ad_structure_collection"] = true;
            jobData["local_group_collection"] = true;
            jobData["session_collection"] = true;

            HttpResponseMessage response = await adminClient.CreateJobAsync(ingestClient["id"].ToString(), jobData.Value<bool>("ad_structure_collection"),
                jobData.Value<bool>("all_trusted_domains"), jobData["domains"]?.ToObject<string[]>(), jobData.Value<bool>("local_group_collection"),
                jobData["ous"]?.ToObject<string[]>(), jobData.Value<bool>("session_collection"));
            Console.WriteLine($"[*] Response: {response}");


            // Create ingest BHE client
            Credentials ingestCredentials = new Credentials(ingestClient["token"]["data"]["id"].ToString(), ingestClient["token"]["data"]["key"].ToString());

            // Proxy settings
            var httpHandler = new HttpClientHandler();
            //var trustAllCerts = new TrustAllCertsPolicy();
            //ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;
            //httpHandler.Proxy = new WebProxy("http://127.0.0.1:8080");

            // Signer
            var authHandler = new AuthSigner(ingestCredentials.TokenKey, ingestCredentials.TokenId, httpHandler);
            var client = new HttpClient(authHandler);
            APIClient signedIngestClient = new APIClient(client, SCHEME, BHE_DOMAIN, PORT, ingestCredentials, userAgent);

            // Get jobs
            Console.WriteLine("[*] Get jobs for client");
            JArray jobs = await signedIngestClient.GetJobsAsync();
            if (jobs.Count == 0)
            {
                Console.WriteLine("[!] No jobs. Schedule an on-demand scan for client and run the script again.");
                return;
            }

            // Tell BHE we are starting the next job
            JObject nextJob = jobs[0] as JObject;
            Console.WriteLine("[*] Starting next job with ID: " + nextJob["id"]);
            response = await signedIngestClient.StartJobAsync((int)nextJob["id"]);
            Console.WriteLine($"[*] Response: {response}");

            // Load JSON file
            Console.WriteLine($"[*] Ingesting SCCMHound data");

            // Ingest data
            response = await signedIngestClient.PostIngestAsync(Encoding.UTF8.GetBytes(jsonToIngest.ToString(Formatting.None)));
            Console.WriteLine($"[*] Response: {response}");


            // Mark job as complete
            Console.WriteLine("[*] Marking job as done");
            response = await signedIngestClient.EndJobAsync();
            Console.WriteLine($"[*] Response: {response}");
        }

        public static void SendIt(JToken BloodHoundData)
        {
            // Get environment variables from %USERPROFILE%\.env
            string basePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string envFilePath = Path.Combine(basePath, ".env");

            if (File.Exists(envFilePath))
            {
                foreach (string line in File.ReadAllLines(envFilePath))
                {
                    string[] parts = line.Split(new[] { '=' }, 2, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2)
                    {
                        string key = parts[0].Trim();
                        string value = parts[1].Trim();
                        Environment.SetEnvironmentVariable(key, value);
                    }
                }
            }

            // Load environment variables
            string DOMAIN = Environment.GetEnvironmentVariable("DOMAIN");
            int PORT = new int();
            int.TryParse(Environment.GetEnvironmentVariable("PORT"), out PORT); 
            string SCHEME = Environment.GetEnvironmentVariable("SCHEME");
            string SHARPHOUND_USER_AGENT = Environment.GetEnvironmentVariable("SHARPHOUND_USER_AGENT");
            string SHARPHOUND_CLIENT_NAME = Environment.GetEnvironmentVariable("SHARPHOUND_CLIENT_NAME");
            string TOKEN_ID = Environment.GetEnvironmentVariable("TOKEN_ID");
            string TOKEN_KEY = Environment.GetEnvironmentVariable("TOKEN_KEY");
            string FILEPATH_ZIP = Environment.GetEnvironmentVariable("FILEPATH_ZIP");

            // Create API client
            Credentials adminCredentials = new Credentials(TOKEN_ID, TOKEN_KEY);
            var httpHandler = new HttpClientHandler();

            // Proxy settings
            //var trustAllCerts = new TrustAllCertsPolicy();
            //ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;
            //httpHandler.Proxy = new WebProxy("http://127.0.0.1:8080");

            // Auth handler
            var authHandler = new AuthSigner(adminCredentials.TokenKey, adminCredentials.TokenId, httpHandler);
            var client = new HttpClient(authHandler);
            var header = new ProductHeaderValue("sharphound",
                Assembly.GetExecutingAssembly().GetName().Version.ToString());
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(header));
            APIClient adminClient = new APIClient(client, SCHEME, DOMAIN, PORT, adminCredentials);

            
            // Prepare data
            JObject obj = BloodHoundData.ToObject<JObject>();

            // Extract the "Content" property for each "Line"
            var result = obj["value"]
                .SelectMany(lineValue => lineValue["Result"])
                .Select(lineResult => new
                {
                    Line = (string)lineResult["Line"],
                    Content = (string)lineResult["Content"],
                    Device = (string)lineResult["Device"]
                })
                .ToList();

            // Create a new JObject to store the extracted content
            JObject contentAsJObject = new JObject();

            foreach (var lineData in result)
            {
                // Parse the "Content" property value for each "Line" as a JObject
                JObject parsedContent = JObject.Parse(lineData.Content);

                // Update the "version" attribute in the "meta" object to 5
                Console.WriteLine($"[*] Setting meta version");
                if (parsedContent["meta"] is JObject metaObject)
                {
                    metaObject["version"] = 5;
                }
                IngestDataFromJSON(adminClient, adminCredentials, SHARPHOUND_CLIENT_NAME, SHARPHOUND_USER_AGENT, parsedContent, DOMAIN, SCHEME, PORT).Wait();

                // Add the parsed content to the result JObject, using the "Line" number as the key
                contentAsJObject[lineData.Line] = parsedContent;
            }
            /*
            
            // ON PREM AD DATA
            if (!string.IsNullOrEmpty(FILEPATH_ZIP))
            {
                string filePathUnzipped = Path.Combine(Path.GetDirectoryName(FILEPATH_ZIP), "unzip");
                string filePathUnzippedResized = Path.Combine(Path.GetDirectoryName(FILEPATH_ZIP), "unzip_resized");

                // Delete output from previous runs
                Directory.CreateDirectory(filePathUnzipped)?.GetFiles("*", SearchOption.AllDirectories).ToList().ForEach(f => f.Delete());
                Directory.CreateDirectory(filePathUnzippedResized)?.GetFiles("*", SearchOption.AllDirectories).ToList().ForEach(f => f.Delete());

                // Unzip BH dir
                Console.WriteLine(FILEPATH_ZIP);
                ZipFile.ExtractToDirectory(FILEPATH_ZIP, filePathUnzipped);

                // Iterate unzipped files
                foreach (string fileName in Directory.EnumerateFiles(filePathUnzipped))
                {
                    string jsonFile = Path.Combine(filePathUnzipped, fileName);

                    // Convert files from utf-8-sig to utf-8
                    RemoveBOM(jsonFile);

                    // Set meta version to 0 like in SH enterprise.
                    // Current FOSS version is 5. If 5 is used, local groups and sessions will not be considered by BHE
                    SetMetaVersion(jsonFile, 0);

                    // Split file so it's not too large
                    SplitFile(jsonFile, filePathUnzippedResized, 20000).Wait();
                }

                // Ingest data
                IngestDataFromFolder(adminClient, adminCredentials, SHARPHOUND_CLIENT_NAME, SHARPHOUND_USER_AGENT, filePathUnzippedResized, BHE_DOMAIN, SCHEME, PORT).Wait();
            }
           */
        }
    }

    public static class TrustDirectionLookup
    {
        public static readonly Dictionary<int, string> Values = new Dictionary<int, string>()
        {
            { 0, "Disabled" },
            { 1, "Inbound" },
            { 2, "Outbound" },
            { 3, "Bidirectional" }
        };
    }

    public static class TrustTypeLookup
    {
        public static readonly Dictionary<int, string> Values = new Dictionary<int, string>()
        {
            { 0, "ParentChild" },
            { 1, "CrossLink" },
            { 2, "Forest" },
            { 3, "External" },
            { 4, "Unknown" }
        };
    }
}