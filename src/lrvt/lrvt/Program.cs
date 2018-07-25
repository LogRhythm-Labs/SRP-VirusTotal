using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Collections;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace lrvt
{
    // VirusTotal Response Class - Matches data returned after submitting a file to VirusTotal
    // TO DO: This could (and maybe should) utilize a struct instead of a class due to how simple it is

    public class VirusTotalResponse
    {
        public string permalink;
        public string resource;
        public int response_code;
        public string scan_id;
        public string verbose_msg;
        public string sha256;
    }

    // VirusTotal URL Response Class - Matches data returned after submitting a URL to VirusTotal
    // TO DO: This could (and maybe should) utilize a struct instead of a class due to how simple it is

    public class VirusTotalUrlResponse
    {
        public string permalink;
        public string resource;
        public string url;
        public int response_code;
        public string scan_date;
        public string scan_id;
        public string verbose_msg;
    }

    // Static class with methods for dynamically iterating through VirusTotal scan result data. This is helpful because the list of VirusTotal scan engines can change, scan contents can change, etc. 

    public static class VtReflect
    {
        // Return an object's (typically a VirusTotal scan result field/parameter) value; type agnostic

        public static Object GetPropValue(this Object obj, string name)
        {
            foreach (String part in name.Split('.'))
            {
                if (obj == null) { return null; }

                Type type = obj.GetType();
                PropertyInfo info = type.GetProperty(part);
                if (info == null) { return null; }

                obj = info.GetValue(obj, null);
            }
            return obj;
        }

        public static T GetPropValue<T>(this Object obj, String name)
        {
            Object retval = GetPropValue(obj, name);
            if (retval == null) { return default(T); }

            // throws InvalidCastException if types are incompatible
            return (T)retval;
        }
    }

    class Program
    {
        // VirusTotal API URI Definitions - Additional API URI(s) should can be added below for additional functionality in the future
        // TO DO: We may want to make these strings actual constants

        public static string vt_filescan_uri = @"https://www.virustotal.com/vtapi/v2/file/scan";
        public static string vt_report_uri = @"https://www.virustotal.com/vtapi/v2/file/report";
        public static string vt_scanurl_uri = @"https://www.virustotal.com/vtapi/v2/url/scan";
        public static string vt_reporturl_uri = @"https://www.virustotal.com/vtapi/v2/url/report";

        // ┌────────────────────────────────────────────────────────────┐
        // │	VirusTotal API Request Methods							│
        // └────────────────────────────────────────────────────────────┘

        // Upload/submit file to VirusTotal for scanning

        public static byte[] VtUploadFile(byte[] file_bytes, string file_name, string content_type, string url_string, string api_key)
        {
            var webclient = new WebClient();
            string boundary = "------------------------" + DateTime.Now.Ticks.ToString("x");
            webclient.Headers.Add("Content-Type", "multipart/form-data; boundary=" + boundary);
            var file_data = webclient.Encoding.GetString(file_bytes);
            var package = String.Format("--{0}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n{3}\r\n--{0}\r\nContent-Disposition: form-data; name=\"apikey\"\r\n\r\n{4}\r\n--{0}--\r\n", boundary, file_name, content_type, file_data, api_key);
            var stream_data = webclient.Encoding.GetBytes(package);
            byte[] resp = webclient.UploadData(url_string, "POST", stream_data);

            return resp;
        }

        // Submit URL to VirusTotal for scanning

        public static byte[] VtScanUrl(string target_url, string content_type, string url_string, string api_key)
        {
            var webclient = new WebClient();
            webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            var package = String.Format("apikey={0}&url={1}", api_key, target_url);
            var stream_data = webclient.Encoding.GetBytes(package);
            byte[] resp = webclient.UploadData(url_string, "POST", stream_data);

            return resp;
        }

        // Retrieve VirusTotal scan report

        public static byte[] VtGetReport(string resource_name, string url_string, string api_key)
        {
            string content_type = "application/x-www-form-urlencoded";
            var webclient = new WebClient();
            webclient.Headers.Add("Content-Type", content_type);
            var package = String.Format("apikey={0}&resource={1}", api_key, resource_name);
            var stream_data = webclient.Encoding.GetBytes(package);
            byte[] resp = webclient.UploadData(url_string, "POST", stream_data);

            return resp;
        }

        // ┌────────────────────────────────────────────────────────────┐
        // │	Misc/Helper Methods										│
        // └────────────────────────────────────────────────────────────┘

        public static VirusTotalResponse ConvertResponse(byte[] response_bytes)
        {
            string response_string = Encoding.ASCII.GetString(response_bytes);
            VirusTotalResponse vtr = JsonConvert.DeserializeObject<VirusTotalResponse>(response_string);
            return vtr;
        }

        public static VirusTotalUrlResponse ConvertUrlResponse(byte[] response_bytes)
        {
            string response_string = Encoding.ASCII.GetString(response_bytes);
            VirusTotalUrlResponse vtru = JsonConvert.DeserializeObject<VirusTotalUrlResponse>(response_string);
            return vtru;
        }

        public static bool CheckResponseStatus(byte[] report_bytes)
        {
            JObject jobj = JsonConvert.DeserializeObject<JObject>(Encoding.ASCII.GetString(report_bytes));
            int resp_code = (int)jobj.GetValue("response_code");
            if (resp_code == 1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }


        // This function has been deprecated and isn't needed anymore, however I'm leaving it in place until the next major SmartResponse plugin update just in case.
        /*public static string TOGetPermaLink(byte[] report_bytes)
        {
            JObject jobj = JsonConvert.DeserializeObject<JObject>(Encoding.ASCII.GetString(report_bytes));
            string permalink = (string)jobj.GetValue("permalink");
            return permalink;
        }*/

        public static void OutputUrlReport(byte[] report_bytes)
        {
            JObject jobj = JsonConvert.DeserializeObject<JObject>(Encoding.ASCII.GetString(report_bytes));

            int scan_total = Convert.ToInt32((string)jobj.GetValue("total"));
            int scan_posi = Convert.ToInt32((string)jobj.GetValue("positives"));
            decimal hit_ratio = new decimal();

            if (scan_posi == 0)
            {
                hit_ratio = 0M;
            }
            else
            {
                hit_ratio = (decimal)((decimal)scan_posi / (decimal)scan_total);
            }

            string strhit_ratio = hit_ratio.ToString("P");

            string output_text = "Virus Total URL Scan Results\r\n\r\n";

            if (scan_posi > 0)
            {
                string str_scan_list = "";
                JObject scan_tok = (JObject)jobj.GetValue("scans");
                IList<JToken> scan_list = scan_tok.Children().ToList();
                foreach (JToken jt in scan_list)
                {
                    if ((string)jt.First()["detected"] == "True")
                    {
                        str_scan_list += "Engine Name:\t" + (string)jt.GetPropValue<string>("Name");
                        // I believe the VT output format changed at some point in the past, with a parameter being renamed from "detected" to "result"; leaving the below line of code until I can verify its safe to completely remove
                        //str_scan_list += "\r\nDetected:\t" + (string)jt.First()["detected"];
                        str_scan_list += "\r\nResult:\t\t" + (string)jt.First()["result"] + "\r\n\r\n";
                    }
                }

                output_text += "Target URL: " + (string)jobj.GetValue("url") + "\r\n\r\nScan Date: " + (string)jobj.GetValue("scan_date") + "\r\nMalicious Detections: " + (string)jobj.GetValue("positives") + "\r\nTotal Scans: " + (string)jobj.GetValue("total") + "\r\n% Flagged Malicious: " + strhit_ratio + "\r\nPerma-link: " + (string)jobj.GetValue("permalink") + "\r\n\r\nThe following scan engines flagged the URL as malicious:\r\n\r\n" + str_scan_list;
            }
            else
            {
                output_text += "Target URL: " + (string)jobj.GetValue("url") + "\r\n\r\nScan Date: " + (string)jobj.GetValue("scan_date") + "\r\nMalicious Detections: " + (string)jobj.GetValue("positives") + "\r\nTotal Scans: " + (string)jobj.GetValue("total") + "\r\n% Flagged Malicious: " + strhit_ratio + "\r\nPerma-link: " + (string)jobj.GetValue("permalink") + "\r\n\r\nNo scan engines flagged URL as being malicious.";
            }

            Console.WriteLine(output_text);
            return;
        }

        public static void OutputFileReport(byte[] report_bytes, string scanned_filename)
        {
            JObject jobj = JsonConvert.DeserializeObject<JObject>(Encoding.ASCII.GetString(report_bytes));

            int scan_total = Convert.ToInt32((string)jobj.GetValue("total"));
            int scan_posi = Convert.ToInt32((string)jobj.GetValue("positives"));
            decimal hit_ratio = new decimal();

            if (scan_posi == 0)
            {
                hit_ratio = 0M;
            }
            else
            {
                hit_ratio = (decimal)((decimal)scan_posi / (decimal)scan_total);
            }

            string strhit_ratio = hit_ratio.ToString("P");

            string output_text = "Virus Total File Scan Results\r\n\r\n";

            if (scan_posi > 0)
            {
                string str_scan_list = "";
                JObject scan_tok = (JObject)jobj.GetValue("scans");
                IList<JToken> scan_list = scan_tok.Children().ToList();
                foreach (JToken jt in scan_list)
                {
                    if ((string)jt.First()["detected"] == "True")
                    {
                        str_scan_list += "Engine Name:\t\t" + (string)jt.GetPropValue<string>("Name");
                        str_scan_list += "\r\nResult/Threat Name:\t" + (string)jt.First()["result"];
                        str_scan_list += "\r\nEngine Updated:\t\t" + (string)jt.First()["update"];
                        str_scan_list += "\r\nScan Version:\t\t" + (string)jt.First()["version"] + "\r\n\r\n";
                    }
                }

                output_text += "File Name: " + scanned_filename + "\r\n\r\nScan Date: " + (string)jobj.GetValue("scan_date") + "\r\nMalicious Detections: " + (string)jobj.GetValue("positives") + "\r\nTotal Scans: " + (string)jobj.GetValue("total") + "\r\n% Flagged Malicious: " + strhit_ratio + "\r\nFile MD5 Hash: " + (string)jobj.GetValue("md5") + "\r\nFile SHA1 Hash: " + (string)jobj.GetValue("sha1") + "\r\nFile SHA256 Hash: " + (string)jobj.GetValue("sha256") + "\r\nPerma-link: " + (string)jobj.GetValue("permalink") + "\r\n\r\nThe following scan engines flagged the file as malicious:\r\n\r\n" + str_scan_list;
            }
            else
            {
                output_text += "File Name: " + scanned_filename + "\r\n\r\nScan Date: " + (string)jobj.GetValue("scan_date") + "\r\nMalicious Detections: " + (string)jobj.GetValue("positives") + "\r\nTotal Scans: " + (string)jobj.GetValue("total") + "\r\n% Flagged Malicious: " + strhit_ratio + "\r\nFile MD5 Hash: " + (string)jobj.GetValue("md5") + "\r\nFile SHA1 Hash: " + (string)jobj.GetValue("sha1") + "\r\nFile SHA256 Hash: " + (string)jobj.GetValue("sha256") + "\r\nPerma-link: " + (string)jobj.GetValue("permalink") + "\r\n\r\nNo scan engines flagged file as being malicious.";
            }

            Console.WriteLine(output_text);
            return;
        }

        // ┌────────────────────────────────────────────────────────────┐
        // │	Main Method												│
        // └────────────────────────────────────────────────────────────┘

        // Upon execution, main function reads/checks the first CLI arg to see if it is a valid action string; if so, it verifies the other CLI args are present for the relevant action then calls the VirusTotal API
        // TO DO: There may be some redundancy in the various switch branches below with checking args; we can probably simplify this.

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("LogRhythm VirusTotal Query\r\n\r\nAvailable queries:\r\n\r\nScan File\r\nScan URL\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-file [FILE_NAME] [VIRUSTOTAL_API_KEY]\r\nlrvt.exe --scan-url [URL] [VIRUSTOTAL_API_KEY]");
            }
            else
            {
                switch (args[0])
                {
                    case "--scan-url":
                        if (args.Length == 1)
                        {
                            Console.WriteLine("No URL specified and no VirusTotal API key specified!\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-url [URL] [VIRUSTOTAL_API_KEY]\r\n");
                            break;
                        }
                        else
                        {
                            if (args.Length != 3)
                            {
                                Console.WriteLine("No VirusTotal API key specified!\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-url [URL] [VIRUSTOTAL_API_KEY]\r\n");
                                break;
                            }
                            else
                            {
                                try
                                {
                                    byte[] url_resp_bytes = VtScanUrl(args[1], "application/x-www-form-urlencoded", vt_scanurl_uri, args[2]);
                                    VirusTotalUrlResponse vt_urlsub_resp = ConvertUrlResponse(url_resp_bytes);
                                    if (vt_urlsub_resp.response_code != 1)
                                    {
                                        Console.WriteLine("Error submitting URL to VirusTotal!\r\n\r\nError Information:\r\n{0}", vt_urlsub_resp.verbose_msg);
                                        break;
                                    }
                                    else
                                    {
                                        bool has_ret_resp = false;
                                        int retry_count = 0;
                                        bool resp_check = false;
                                        System.Threading.Thread.Sleep(15000);
                                        while (has_ret_resp == false && retry_count < 8)
                                        {
                                            byte[] url_report_bytes = VtGetReport(vt_urlsub_resp.resource, vt_reporturl_uri, args[2]);
                                            if (url_report_bytes != null && url_report_bytes.Length != 0)
                                            {
                                                // ***API TROUBLESHOOTING/DEBUG HELPER OPTION*** Output each response check to stdout. (Uncomment the following 2 lines)
                                                //Console.WriteLine(Encoding.ASCII.GetString(url_report_bytes));
                                                //Console.WriteLine();

                                                resp_check = CheckResponseStatus(url_report_bytes);
                                            }
                                            if (resp_check == true)
                                            {
                                                has_ret_resp = true;
                                                OutputUrlReport(url_report_bytes);
                                                return;
                                            }
                                            else
                                            {
                                                System.Threading.Thread.Sleep(30000);
                                                retry_count++;
                                            }
                                        }

                                        Console.WriteLine("Query took longer than 120 seconds to respond! Please check the scan's permalink, available at:\r\n{0}", vt_urlsub_resp.permalink);
                                        break;
                                    }
                                }

                                catch (Exception u)
                                {
                                    Console.WriteLine("Error submitting URL to VirusTotal!\r\n\r\nError Information:\r\n{0}", u.Message);
                                    break;
                                }
                            }
                        }

                    case "--scan-file":
                        if (args.Length == 1)
                        {
                            Console.WriteLine("No file name specified and no VirusTotal API key specified!\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-file [FILE_NAME] [VIRUSTOTAL_API_KEY]\r\n");
                            break;
                        }
                        else
                        {
                            if (args.Length != 3)
                            {
                                Console.WriteLine("No VirusTotal API key specified!\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-file [FILE_NAME] [VIRUSTOTAL_API_KEY]\r\n");
                                break;
                            }
                            else
                            {
                                if (File.Exists(args[1]) == false)
                                {
                                    Console.WriteLine("File \"{0}\" not found!\r\nPlease verify file name is valid; if file name contains spaces, try wrapping the name in double-quotes.", args[1]);
                                    break;
                                }
                                else
                                {
                                    try
                                    {
                                        byte[] file_bytes = File.ReadAllBytes(args[1]);
                                        byte[] file_resp_bytes = VtUploadFile(file_bytes, Path.GetFileName(args[1]), "application/octet-stream", vt_filescan_uri, args[2]);
                                        VirusTotalResponse vt_filesub_resp = ConvertResponse(file_resp_bytes);
                                        if (vt_filesub_resp.response_code != 1)
                                        {
                                            Console.WriteLine("Error submitting file to VirusTotal!\r\n\r\nError Information:\r\n{0}", vt_filesub_resp.verbose_msg);
                                            break;
                                        }
                                        else
                                        {
                                            bool has_ret_resp = false;
                                            int retry_count = 0;
                                            System.Threading.Thread.Sleep(20000);
                                            while (has_ret_resp == false && retry_count < 8)
                                            {
                                                //System.Threading.Thread.Sleep(30000);
                                                bool resp_check = false;
                                                byte[] file_chk_bytes = VtGetReport(vt_filesub_resp.resource, vt_report_uri, args[2]);
                                                if (file_chk_bytes != null && file_chk_bytes.Length != 0)
                                                {
                                                    // ***API TROUBLESHOOTING/DEBUG HELPER OPTION*** Output each response check to stdout. (Uncomment the following 2 lines)
                                                    //Console.WriteLine(Encoding.ASCII.GetString(file_chk_bytes));
                                                    //Console.WriteLine();

                                                    resp_check = CheckResponseStatus(file_chk_bytes);
                                                }
                                                if (resp_check == true)
                                                {
                                                    has_ret_resp = true;
                                                    OutputFileReport(file_chk_bytes, Path.GetFileName(args[1]));
                                                    return;
                                                }
                                                else
                                                {
                                                    System.Threading.Thread.Sleep(30000);
                                                    retry_count++;
                                                }
                                            }

                                            Console.WriteLine("Query took longer than 240 seconds to respond! Please check the scan's permalink, available at:\r\n{0}", vt_filesub_resp.permalink);
                                            break;
                                        }
                                    }
                                    catch (Exception f)
                                    {
                                        Console.WriteLine("Error submitting file to VirusTotal!\r\n\r\nError Information:\r\n{0}", f.Message);
                                        break;
                                    }
                                }
                            }
                        }

                    default:
                        if (args[0] == "--scan-file" || args[0] == "--scan-url")
                        {
                            Console.WriteLine("Missing argument(s) in command! Available actions: Scan File or Scan URL\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-file [FILE_NAME] [VIRUSTOTAL_API_KEY]\r\nlrvt.exe --scan-url [URL] [VIRUSTOTAL_API_KEY]");
                        }
                        else
                        {
                            Console.WriteLine("Invalid (or no) action specified! Available actions: Scan File or Scan URL\r\n\r\nSyntax:\r\n\r\nlrvt.exe --scan-file [FILE_NAME] [VIRUSTOTAL_API_KEY]\r\nlrvt.exe --scan-url [URL] [VIRUSTOTAL_API_KEY]");
                        }
                        break;
                }

                return;
            }
        }
    }
}
