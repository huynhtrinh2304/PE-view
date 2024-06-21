using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PEview
{
    public class HexDumpFile
    {
        // Phương thức ReadBytes để đọc từng byte của file
        public IEnumerable<byte> ReadBytes(string filePath, long offset, int chunksize = 8192)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                byte[] buffer = new byte[chunksize];
                int bytesRead;
                while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        yield return buffer[i];
                    }
                }
            }
        }

        public  bool IsPrintableCharacter(byte s)
        {

            if (!(s < 127 && s >= 32))
            {
                return false;
            }

            return true;
        }

        public string ValidateByteAsPrintable(byte byteValue)
        {
            if (IsPrintableCharacter(byteValue))
            {
                char a = (char)byteValue;
                string charRT = string.Format(" {0}", a.ToString());

                return charRT;
            }
            else
            {

                return " .";
            }
        }

        public string ReadHexDump(string filePath, int offset = 0, int size = -1)
        {
            StringBuilder result = new StringBuilder();
            int memoryAddress = 0;
            StringBuilder asciiString = new StringBuilder();
            int count = 0;

            foreach (byte b in ReadBytes(filePath, offset))
            {
                asciiString.Append(ValidateByteAsPrintable(b));
                if (memoryAddress % 16 == 0)
                {
                    if (size != -1 && count == size)
                    {
                        break;
                    }

                    result.AppendFormat("{0:X8}: {1:X2} ", memoryAddress + offset, b);
                }
                else if (memoryAddress % 16 == 15)
                {
                    result.AppendFormat("{0:X2} |{1}|\n", b, asciiString.ToString());

                    asciiString.Clear();
                }
                else
                {   
                    result.AppendFormat("{0:X2} ", b);
                }
                memoryAddress++;
                count++;
            }
            return result.ToString();
        }

        public void ExcuteFilePy(string filePath)
        {
            Process process = new Process();
            process.StartInfo.FileName = "C:\\Users\\trinhhuynh\\Desktop\\pefiledata\\.venv\\Scripts\\python.exe";
            process.StartInfo.Arguments = "C:\\Users\\trinhhuynh\\Desktop\\pefiledata\\main.py " + filePath;
            process.Start();
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;

            // Bắt đầu quá trình
            process.Start();

            // Đọc đầu ra và lỗi (nếu có)
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            // Hiển thị đầu ra và lỗi
            Console.WriteLine("Output: " + output);
            Console.WriteLine("Error: " + error);

            // Chờ quy trình con kết thúc
            process.WaitForExit();
        }

        public List<string> CutPath(string str)
        {
            List<string> list = new List<string>();

            string[] parts = str.Split(new char[] { ' ' }, 2);
            string md5 = "";
            string path = "";
            if (parts.Length == 2)
            {
                md5 = parts[0];
                path = parts[1];
            }
            list.Add(md5);
            list.Add(path);
            return list;
        }
    }
}
