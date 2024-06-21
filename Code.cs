using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Windows.Forms.VisualStyles;
using System.Reflection;
using System.IO.Ports;
using System.Globalization;

namespace PEview
{
    public class Code
    {
        public Dictionary<string, List<string>> ReadSections(string md5)
        {
            var sections = new Dictionary<string, List<string>>();

            string filePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json";

            string json = File.ReadAllText(filePath);

            List<SectionHeader> sectionJsonHeader = JsonConvert.DeserializeObject<List<SectionHeader>>(json);

            foreach (SectionHeader section in sectionJsonHeader)
            {

                if (md5 == section.MD5)
                {
                    int countTemp = 0;

                    string replaced = section.Name.Value.Replace("\\x00", "\x00");
                    string name_value = StringToHex(replaced);
                    var value = new Dictionary<string, object>();
                    string[][] sectionNames = ListArrayData.GetSectionNames();

                    for (int i = 0; i < sectionNames.Length; i++)
                    {
                        var values = new List<string>();

                        if (sectionNames[i][0] == "Name")
                        {
                            values.Add(section.Name.FileOffset.ToString("X8"));
                            values.Add(name_value);
                            values.Add(sectionNames[i][1]);
                            values.Add(section.Name.Value.Replace("\\x00", ""));

                            sections.Add(countTemp.ToString(),values);

                        }
                        else if (sectionNames[i][0] == "Misc_VirtualSize")
                        {
                            values.Add(section.Misc_VirtualSize.FileOffset.ToString("X8"));
                            values.Add(section.Misc_VirtualSize.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "VirtualAddress")
                        {
                            values.Add(section.VirtualAddress.FileOffset.ToString("X8"));
                            values.Add(section.VirtualAddress.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "SizeOfRawData")
                        {
                            values.Add(section.SizeOfRawData.FileOffset.ToString("X8"));
                            values.Add(section.SizeOfRawData.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "PointerToRawData")
                        {
                            values.Add(section.PointerToRawData.FileOffset.ToString("X8"));
                            values.Add(section.PointerToRawData.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "PointerToRelocations")
                        {
                            values.Add(section.PointerToRelocations.FileOffset.ToString("X8"));
                            values.Add(section.PointerToRelocations.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "PointerToLinenumbers")
                        {
                            values.Add(section.PointerToLinenumbers.FileOffset.ToString("X8"));
                            values.Add(section.PointerToLinenumbers.Value.ToString("X8"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "NumberOfRelocations")
                        {
                            values.Add(section.NumberOfRelocations.FileOffset.ToString("X8"));
                            values.Add(section.NumberOfRelocations.Value.ToString("X4"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "NumberOfLinenumbers")
                        {
                            values.Add(section.NumberOfLinenumbers.FileOffset.ToString("X8"));
                            values.Add(section.NumberOfLinenumbers.Value.ToString("X4"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }
                        else if (sectionNames[i][0] == "Characteristics")
                        {
                            values.Add(section.Characteristics.FileOffset.ToString("X8"));
                            values.Add(section.Characteristics.Value.ToString("X"));
                            values.Add(sectionNames[i][1]);
                            values.Add("");
                            sections.Add(countTemp.ToString(), values);
                        }

                        countTemp++;
                    }

                    foreach (var flag in section.Flags)
                    {
                        var values = new List<string>();
                        values.Add(" ");
                        values.Add(" ");
                        values.Add(" ");
                        values.Add(flag);

                        sections.Add(countTemp.ToString(),values);
                        countTemp++;
                    }

                }
            }

            return sections;
        }

        public List<List<string>> ReadDosHeader()
        {
            var dataDosHeader = new List<List<string>>();

            string filePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DOS_HEADER.json";
            string json = File.ReadAllText(filePath);

            // conver json -> {}
            DosHeader sectionJsonHeader = JsonConvert.DeserializeObject<DosHeader>(json);

            string[][] sectionNames = ListArrayData.GetDosHeader();


            foreach (var dosHeaderValue in sectionNames)
            {

                List<string> itemDos = new List<string>();


                if (dosHeaderValue[0] == "e_res")
                {
                    itemDos.Clear();

                    List<string> temp = new List<string>();
                    string[] parts = sectionJsonHeader.e_res.Value.Split('\\');

                    //chuyen //x00 thanh 00
                    foreach (string part in parts)
                    {
                        if (part.Length >= 2)
                        {
                            temp.Add(part.Substring(1));
                        }
                    }

                    for (int index = 0; index < 4; index++)
                    {
                        string data1 = (sectionJsonHeader.e_res.FileOffset + index * 2).ToString("X8");
                        string data2 = temp[index * 2] + temp[index * 2 + 1];
                        string data3 = dosHeaderValue[1];
                        itemDos.Add(data1);
                        itemDos.Add(data2);
                        itemDos.Add(data3);
                        itemDos.Add("");
                    }
                    dataDosHeader.Add(itemDos);
                }
                else if (dosHeaderValue[0] == "e_res2")
                {
                    itemDos.Clear();

                    List<string> temp = new List<string>();
                    string[] parts = sectionJsonHeader.e_res2.Value.Split('\\');


                    //chuyen //x00 thanh 00
                    foreach (string part in parts)
                    {
                        if (part.Length >= 2)
                        {
                            temp.Add(part.Substring(1));
                        }
                    }

                    for (int index = 0; index < 10; index++)
                    {
                        string data1 = (sectionJsonHeader.e_res2.FileOffset + index * 2).ToString("X8");
                        string data2 = temp[index * 2] + temp[index * 2 + 1];
                        string data3 = dosHeaderValue[1];
                        itemDos.Add(data1);
                        itemDos.Add(data2);
                        itemDos.Add(data3);
                        itemDos.Add("");
                    }
                    dataDosHeader.Add(itemDos);
                }
                else if (dosHeaderValue[0] == "e_cblp" ||
                    dosHeaderValue[0] == "e_cp" ||
                    dosHeaderValue[0] == "e_crlc" ||
                    dosHeaderValue[0] == "e_cparhdr" ||
                    dosHeaderValue[0] == "e_minalloc" ||
                    dosHeaderValue[0] == "e_maxalloc" ||
                    dosHeaderValue[0] == "e_ss" ||
                    dosHeaderValue[0] == "e_sp" ||
                    dosHeaderValue[0] == "e_csum" ||
                    dosHeaderValue[0] == "e_ip" ||
                    dosHeaderValue[0] == "e_cs" ||
                    dosHeaderValue[0] == "e_lfarlc" ||
                    dosHeaderValue[0] == "e_ovno" ||
                    dosHeaderValue[0] == "e_oemid" ||
                    dosHeaderValue[0] == "e_oeminfo" ||
                    dosHeaderValue[0] == "e_lfanew" ||
                    dosHeaderValue[0] == "e_magic")
                {
                    itemDos.Clear();

                    List<string> temp = new List<string>();
                    string pFile = "";
                    string data = "";
                    string value = "";

                    if (dosHeaderValue[0] == "e_cblp")
                    {
                        pFile = (sectionJsonHeader.e_cblp.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_cblp.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_cp")
                    {
                        pFile = (sectionJsonHeader.e_cp.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_cp.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_crlc")
                    {
                        pFile = (sectionJsonHeader.e_crlc.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_crlc.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_cparhdr")
                    {
                        pFile = (sectionJsonHeader.e_cparhdr.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_cparhdr.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_minalloc")
                    {
                        pFile = (sectionJsonHeader.e_minalloc.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_minalloc.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_maxalloc")
                    {
                        pFile = (sectionJsonHeader.e_maxalloc.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_maxalloc.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_ss")
                    {
                        pFile = (sectionJsonHeader.e_ss.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_ss.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_sp")
                    {
                        pFile = (sectionJsonHeader.e_sp.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_sp.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_csum")
                    {
                        pFile = (sectionJsonHeader.e_csum.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_csum.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_ip")
                    {
                        pFile = (sectionJsonHeader.e_ip.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_ip.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_cs")
                    {
                        pFile = (sectionJsonHeader.e_cs.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_cs.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_cp")
                    {
                        pFile = (sectionJsonHeader.e_cp.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_cp.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_lfarlc")
                    {
                        pFile = (sectionJsonHeader.e_lfarlc.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_lfarlc.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_ovno")
                    {
                        pFile = (sectionJsonHeader.e_ovno.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_ovno.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_oemid")
                    {
                        pFile = (sectionJsonHeader.e_oemid.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_oemid.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_oeminfo")
                    {
                        pFile = (sectionJsonHeader.e_oeminfo.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_oeminfo.Value).ToString("X4");
                    }
                    else if (dosHeaderValue[0] == "e_lfanew")
                    {
                        pFile = (sectionJsonHeader.e_lfanew.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_lfanew.Value).ToString("X8");
                    }
                    else if (dosHeaderValue[0] == "e_magic")
                    {
                        pFile = (sectionJsonHeader.e_magic.FileOffset).ToString("X8");
                        data = (sectionJsonHeader.e_magic.Value).ToString("X4");
                        value = sectionJsonHeader.Structure + " MZ";
                    }

                    string data1 = pFile;
                    string data2 = data;
                    string data3 = dosHeaderValue[1];
                    string data4 = value;
                    itemDos.Add(data1);
                    itemDos.Add(data2);
                    itemDos.Add(data3);
                    itemDos.Add(data4);

                    dataDosHeader.Add(itemDos);
                }


            }

            return dataDosHeader;

        }

        public List<string> ReadSignature()
        {
            List<string> dataSig = new List<string>();
            string filePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\NT_HEADERS.json";
            string json = File.ReadAllText(filePath);

            // conver json -> {}
            NTHeader sectionJsonHeader = JsonConvert.DeserializeObject<NTHeader>(json);


            string data1 = (sectionJsonHeader.Signature.FileOffset).ToString("X8"); ;
            string data2 = (sectionJsonHeader.Signature.Value).ToString("X8");
            string data3 = "Singature";
            string data4 = "IMAGE_NT_SINGATURE PE";
            dataSig.Add(data1);
            dataSig.Add(data2);
            dataSig.Add(data3);
            dataSig.Add(data4);

            return dataSig;

        }

        public List<List<string>> ReadFileHeader()
        {
            var dataFileHeader = new List<List<string>>();

            string fileHeaderPath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\FILE_HEADER.json";
            string fileHeaderPathJson = File.ReadAllText(fileHeaderPath);


            string flagsPath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\Flags.json";
            string readFlagsJson = File.ReadAllText(flagsPath);

            // conver json -> {}
            FileHeader FileHeaderJson = JsonConvert.DeserializeObject<FileHeader>(fileHeaderPathJson);

            //du lieu json
            string[] flagsJson = JsonConvert.DeserializeObject<string[]>(readFlagsJson);


            string[][] FILE_HEADER_NAMES = ListArrayData.FILE_HEADER_NAMES();

            foreach (var file_header_name in FILE_HEADER_NAMES)
            {
                List<string> itemFileHeader = new List<string>();
                string value = "";
                string data = "";
                string pFile = "";
                string description = "";
                if (file_header_name[0] == "TimeDateStamp")
                {
                    itemFileHeader.Clear();
                    List<string> temp = new List<string>();
                    

                    int spaceIndex = FileHeaderJson.TimeDateStamp.Value.IndexOf(' ');
                    Console.WriteLine(spaceIndex);

                    if (spaceIndex == 3)
                    {
                        data = "0000000";
                        value = "";
                    }
                    else
                    {
                        data = FileHeaderJson.TimeDateStamp.Value.Substring(2, spaceIndex - 2);
                        value = FileHeaderJson.TimeDateStamp.Value.Substring(spaceIndex + 2, spaceIndex + 18);
                    }

                    pFile = FileHeaderJson.TimeDateStamp.FileOffset.ToString("X8");
                    
                }
                else
                {

                    if (file_header_name[0] == "Machine")
                    {
                        pFile = (FileHeaderJson.Machine.FileOffset).ToString("X8");
                        data = (FileHeaderJson.Machine.Value).ToString("X4");

                        string[][] MACHINE_NAMES_AND_VALUES = ListArrayData.MACHINE_NAMES_AND_VALUES();


                        foreach (var machine_name_and_value in MACHINE_NAMES_AND_VALUES)
                        {
                            if (data == int.Parse(machine_name_and_value[0]).ToString("X4"))
                            {
                                value = machine_name_and_value[1];
                            }
                        }
                    }
                    else if (file_header_name[0] == "NumberOfSections")
                    {
                        pFile = (FileHeaderJson.NumberOfSections.FileOffset).ToString("X8");
                        data = (FileHeaderJson.NumberOfSections.Value).ToString("X4");
                    }
                    else if (file_header_name[0] == "PointerToSymbolTable")
                    {
                        pFile = (FileHeaderJson.PointerToSymbolTable.FileOffset).ToString("X8");
                        data = (FileHeaderJson.PointerToSymbolTable.Value).ToString("X8");
                    }
                    else if (file_header_name[0] == "NumberOfSymbols")
                    {
                        pFile = (FileHeaderJson.NumberOfSymbols.FileOffset).ToString("X8");
                        data = (FileHeaderJson.NumberOfSymbols.Value).ToString("X8");
                    }
                    else if (file_header_name[0] == "SizeOfOptionalHeader")
                    {
                        pFile = (FileHeaderJson.SizeOfOptionalHeader.FileOffset).ToString("X8");
                        data = (FileHeaderJson.SizeOfOptionalHeader.Value).ToString("X4");
                    }
                    else if (file_header_name[0] == "Characteristics")
                    {
                        pFile = (FileHeaderJson.Characteristics.FileOffset).ToString("X8");
                        data = (FileHeaderJson.Characteristics.Value).ToString("X4");
                    }
         
                }

                description = file_header_name[1];

                itemFileHeader.Add(pFile);
                itemFileHeader.Add(data);
                itemFileHeader.Add(description);
                itemFileHeader.Add(value);

                dataFileHeader.Add(itemFileHeader);
            }

            var dataItemFlags = new List<List<string>>();


            foreach (var flagJson in flagsJson)
            {
                List<string> itemFlag = new List<string>();

                string desc = "";

                string[][] CHARACTERISTIC_NAMES_AND_VALUES = ListArrayData.CHARACTERISTIC_NAMES_AND_VALUES();

                foreach (var characteristic_name_and_value in CHARACTERISTIC_NAMES_AND_VALUES)
                {
                    if (characteristic_name_and_value[1] == flagJson)
                    {
                        int intValue = int.Parse(characteristic_name_and_value[0]);
                        desc = intValue.ToString("X4");

                    }    
                }
                itemFlag.Add("");
                itemFlag.Add("");
                itemFlag.Add(desc);
                itemFlag.Add(flagJson);
                dataItemFlags.Add(itemFlag);
            }

            var sortedData = dataItemFlags.OrderBy(item => int.Parse(item[2], NumberStyles.HexNumber)).ToList();
            foreach (var row in sortedData)
            {
                dataFileHeader.Add(row);
            }


            return dataFileHeader;

        }

        public List<List<string>> ReadOptionalHeader()
        {
            var dataOptionalHeader = new List<List<string>>();

            string optionalHeaderPath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\OPTIONAL_HEADER.json";
            string dllCharacteristicsPath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DllCharacteristics.json";
            string dataDirectoryPath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DATA_DIRECTORY.json";


            string optionalHeaderPathJson = File.ReadAllText(optionalHeaderPath);
            string dataDirectoryPathJson = File.ReadAllText(dataDirectoryPath);


            OptionalHeader optinalJsonHeader = JsonConvert.DeserializeObject<OptionalHeader>(optionalHeaderPathJson);
            List<DataDirectory> listDataDirectory = JsonConvert.DeserializeObject<List<DataDirectory>>(dataDirectoryPathJson);


            string[][] OPTIONAL_HEADER_NAMES = ListArrayData.OPTIONAL_HEADER_NAMES();


            foreach (var name in OPTIONAL_HEADER_NAMES)
            {
                List<string> itemOptionalHeader = new List<string>();

                string pFile = "";
                string data = "";

                if (name[0] == "Win32VersionValue")
                {
                    pFile = (optinalJsonHeader.MinorSubsystemVersion.FileOffset + 4).ToString("X8");
                    data = "00000000";

                    itemOptionalHeader.Add(pFile);
                    itemOptionalHeader.Add(data);
                    itemOptionalHeader.Add(name[1]);
                    itemOptionalHeader.Add("");
                }
                else
                {
                    if (name[0] == "DllCharacteristics")
                    {
                        pFile = (optinalJsonHeader.DllCharacteristics.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.DllCharacteristics.Value).ToString("X4");
                    }
                    else if (name[0] == "BaseOfCode")
                    {
                        pFile = (optinalJsonHeader.BaseOfCode.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.BaseOfCode.Value).ToString("X8");
                    }
                    else if (name[0] == "MajorLinkerVersion")
                    {
                        pFile = (optinalJsonHeader.MajorLinkerVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MajorLinkerVersion.Value).ToString("X2");
                    }
                    else if (name[0] == "MinorOperatingSystemVersion")
                    {
                        pFile = (optinalJsonHeader.MinorOperatingSystemVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MinorOperatingSystemVersion.Value).ToString("X4");
                    }
                    else if (name[0] == "MinorLinkerVersion")
                    {
                        pFile = (optinalJsonHeader.MinorLinkerVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MinorLinkerVersion.Value).ToString("X2");
                    }
                    else if (name[0] == "MajorSubsystemVersion")
                    {
                        pFile = (optinalJsonHeader.MajorSubsystemVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MajorSubsystemVersion.Value).ToString("X4");
                    }
                    else if (name[0] == "MajorOperatingSystemVersion")
                    {
                        pFile = (optinalJsonHeader.MajorOperatingSystemVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MajorOperatingSystemVersion.Value).ToString("X4");
                    }
                    else if (name[0] == "SizeOfStackCommit")
                    {
                        pFile = (optinalJsonHeader.SizeOfStackCommit.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfStackCommit.Value).ToString("X4");
                    }
                    else if (name[0] == "SizeOfUninitializedData")
                    {
                        pFile = (optinalJsonHeader.SizeOfUninitializedData.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfUninitializedData.Value).ToString("X8");
                    }
                    else if (name[0] == "NumberOfRvaAndSizes")
                    {
                        pFile = (optinalJsonHeader.NumberOfRvaAndSizes.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.NumberOfRvaAndSizes.Value).ToString("X8");
                    }
                    else if (name[0] == "SizeOfHeapReserve")
                    {
                        pFile = (optinalJsonHeader.SizeOfHeapReserve.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfHeapReserve.Value).ToString("X4");
                    }
                    else if (name[0] == "LoaderFlags")
                    {
                        pFile = (optinalJsonHeader.LoaderFlags.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.LoaderFlags.Value).ToString("X8");
                    }
                    else if (name[0] == "SizeOfHeapCommit")
                    {
                        pFile = (optinalJsonHeader.SizeOfHeapCommit.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfHeapCommit.Value).ToString("X4");
                    }
                    else if (name[0] == "SizeOfStackReserve")
                    {
                        pFile = (optinalJsonHeader.SizeOfStackReserve.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfStackReserve.Value).ToString("X4");
                    }
                    else if (name[0] == "SizeOfHeaders")
                    {
                        pFile = (optinalJsonHeader.SizeOfHeaders.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfHeaders.Value).ToString("X8");
                    }
                    else if (name[0] == "Subsystem")
                    {
                        pFile = (optinalJsonHeader.Subsystem.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.Subsystem.Value).ToString("X4");
                    }
                    else if (name[0] == "Magic")
                    {
                        pFile = (optinalJsonHeader.Magic.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.Magic.Value).ToString("X4");
                    }
                    else if (name[0] == "MinorImageVersion")
                    {
                        pFile = (optinalJsonHeader.MinorImageVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MinorImageVersion.Value).ToString("X4");
                    }
                    else if (name[0] == "MajorImageVersion")
                    {
                        pFile = (optinalJsonHeader.MajorImageVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MajorImageVersion.Value).ToString("X4");
                    }
                    else if (name[0] == "FileAlignment")
                    {
                        pFile = (optinalJsonHeader.FileAlignment.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.FileAlignment.Value).ToString("X8");
                    }
                    else if (name[0] == "BaseOfData")
                    {
                        pFile = (optinalJsonHeader.BaseOfData.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.BaseOfData.Value).ToString("X8");
                    }
                    else if (name[0] == "AddressOfEntryPoint")
                    {
                        pFile = (optinalJsonHeader.AddressOfEntryPoint.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.AddressOfEntryPoint.Value).ToString("X8");
                    }
                    else if (name[0] == "SectionAlignment")
                    {
                        pFile = (optinalJsonHeader.SectionAlignment.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SectionAlignment.Value).ToString("X8");
                    }
                    else if (name[0] == "SizeOfCode")
                    {
                        pFile = (optinalJsonHeader.SizeOfCode.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfCode.Value).ToString("X8");
                    }
                    else if (name[0] == "ImageBase")
                    {
                        pFile = (optinalJsonHeader.ImageBase.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.ImageBase.Value).ToString("X8");
                    }
                    else if (name[0] == "SizeOfInitializedData")
                    {
                        pFile = (optinalJsonHeader.SizeOfInitializedData.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfInitializedData.Value).ToString("X8");
                    }
                    else if (name[0] == "SizeOfImage")
                    {
                        pFile = (optinalJsonHeader.SizeOfImage.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.SizeOfImage.Value).ToString("X8");
                    }
                    else if (name[0] == "CheckSum")
                    {
                        pFile = (optinalJsonHeader.CheckSum.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.CheckSum.Value).ToString("X8");
                    }
                    else if (name[0] == "MinorSubsystemVersion")
                    {
                        pFile = (optinalJsonHeader.MinorSubsystemVersion.FileOffset).ToString("X8");
                        data = (optinalJsonHeader.MinorSubsystemVersion.Value).ToString("X4");
                    }

                    itemOptionalHeader.Add(pFile);
                    itemOptionalHeader.Add(data);
                    itemOptionalHeader.Add(name[1]);
                    itemOptionalHeader.Add("");

                }
                dataOptionalHeader.Add(itemOptionalHeader);

            }

            foreach (var dataDirectory in listDataDirectory)
            {
                List<string> itemOptionalHeader = new List<string>();
                List<string> sizeOptional = new List<string>();

                itemOptionalHeader.Add(dataDirectory.VirtualAddress.FileOffset.ToString("X8"));
                itemOptionalHeader.Add(dataDirectory.VirtualAddress.Value.ToString("X8"));
                itemOptionalHeader.Add("RVA");
                itemOptionalHeader.Add(dataDirectory.Structure);


                sizeOptional.Add(dataDirectory.Size.FileOffset.ToString("X8"));
                sizeOptional.Add(dataDirectory.Size.Value.ToString("X8"));
                sizeOptional.Add("Size");
                sizeOptional.Add("");

                dataOptionalHeader.Add(itemOptionalHeader);
                dataOptionalHeader.Add(sizeOptional);

            }



            return dataOptionalHeader;
        }







        static string StringToHex(string replaced)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(replaced);
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2} ", b);
            }
            return hex.ToString();
        }

        public static List<String> getNameData()
        {
            string jsonFilePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json";
            string jsonData = File.ReadAllText(jsonFilePath);

            // Phân tích cú pháp JSON thành JArray
            JArray jsonArray = JArray.Parse(jsonData);

            // Khởi tạo danh sách để lưu các giá trị Value
            List<string> valueList = new List<string>();

            // Duyệt qua từng phần tử trong JArray và lấy giá trị Value
            foreach (JObject jsonObject in jsonArray)
            {
                string value = jsonObject["Name"]["Value"].ToString().Replace("\\x00", "");
                valueList.Add(value);
            }

            return valueList;
        }

        public static List<int> getDataSection(string md5_1)
        {
            string jsonFilePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json";
            string jsonData = File.ReadAllText(jsonFilePath);

            // Phân tích cú pháp JSON thành JArray
            JArray jsonArray = JArray.Parse(jsonData);

            // Khởi tạo danh sách để lưu các giá trị Value
            List<int> results = new List<int>();

            foreach (JObject obj in jsonArray)
            {
                string md5_2 = obj["MD5"].ToString();

                if (md5_1 == md5_2)
                {
                    int pointer = obj["PointerToRawData"]["Value"].ToObject<int>();
                    int size = obj["SizeOfRawData"]["Value"].ToObject<int>();

                    results.Add(pointer);
                    results.Add(size);

                }
            }
            return results;
        }

        public static List<string> getMd5()
        {
            string jsonFilePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json";
            string jsonData = File.ReadAllText(jsonFilePath);

            // Phân tích cú pháp JSON thành JArray
            JArray jsonArray = JArray.Parse(jsonData);

            // Khởi tạo danh sách để lưu các giá trị Value
            var resultList = new List<string>();

            // Duyệt qua từng phần tử trong JArray và lấy giá trị Value
            foreach (var item in jsonArray)
            {
                string md5 = item["MD5"].ToString();
                resultList.Add(md5);
            }

            return resultList;
        }

        public static int getDosHeaderData()
        {
            string jsonFilePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DOS_HEADER.json";
            string jsonData = File.ReadAllText(jsonFilePath);

            DosHeader sectionJsonHeader = JsonConvert.DeserializeObject<DosHeader>(jsonData);

            // Khởi tạo danh sách để lưu các giá trị Value


            return sectionJsonHeader.e_lfarlc.Value;
        }


    }


}
