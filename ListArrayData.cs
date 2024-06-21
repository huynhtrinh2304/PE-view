using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class ListArrayData
    {
        public static string[][] GetSectionNames()
        {
            return new string[][]
            {
            new string[] { "Name", "Name" },
            new string[] { "Misc_VirtualSize", "Virtual Size" },
            new string[] { "VirtualAddress", "RVA" },
            new string[] { "SizeOfRawData", "Size of Raw Data" },
            new string[] { "PointerToRawData", "Pointer to Raw Data" },
            new string[] { "PointerToRelocations", "Pointer to Relocations" },
            new string[] { "PointerToLinenumbers", "Pointerto Line Numbers" },
            new string[] { "NumberOfRelocations", "Number Of Relocations" },
            new string[] { "NumberOfLinenumbers", "Number of Line Numbers" },
            new string[] { "Characteristics", "Characteristics" }
            };
        }

        public static string[][] GetDosHeader()
        {
            return new string[][]
            {
            new[] { "e_magic", "Signature" },
            new[] { "e_cblp", "Bytes on Last Page of File" },
            new[] { "e_cp", "Pages in File" },
            new[] { "e_crlc", "Relocations" },
            new[] { "e_cparhdr", "Size of Header in Paragraphs" },
            new[] { "e_minalloc", "Minimum Extra Paragraphs Needed" },
            new[] { "e_maxalloc", "Maximum Extra Paragraphs Needed" },
            new[] { "e_ss", "Initial (relative) SS value" },
            new[] { "e_sp", "Initial SP value" },
            new[] { "e_csum", "Checksum" },
            new[] { "e_ip", "Initial IP value" },
            new[] { "e_cs", "Initial (relative) CS value" },
            new[] { "e_lfarlc", "Offset to Relocation Table" },
            new[] { "e_ovno", "Overlay Number" },
            new[] { "e_res", "Reserved Words" },
            new[] { "e_oemid", "OEM Identifier" },
            new[] { "e_oeminfo", "OEM Information" },
            new[] { "e_res2", "Reserved Words" },
            new[] { "e_lfanew", "Offset to New EXE Header" }
            };
        }

        public static string[][] FILE_HEADER_NAMES()
        {
            return new string[][]
            {
            new[] { "Machine", "Machine" },
            new[] { "NumberOfSections", "Number of Sections" },
            new[] { "TimeDateStamp", "Time Date Stamp" },
            new[] { "PointerToSymbolTable", "Pointer to Symbol Table" },
            new[] { "NumberOfSymbols", "Number of Symbols" },
            new[] { "SizeOfOptionalHeader", "Size of Optional Header" },
            new[] { "Characteristics", "Characteristics" },
            };

        }

        public static string[][] MACHINE_NAMES_AND_VALUES()
        {
            return new string[][]
            {
            new[] { "332", "IMAGE_FILE_MACHINE_I386" },
            new[] { "512", "IMAGE_FILE_MACHINE_IA64" },
            new[] { "34404", "IMAGE_FILE_MACHINE_AMD64" }
            };

        }

        public static string[][] CHARACTERISTIC_NAMES_AND_VALUES()
        {
            return new string[][]
            {
            new[] { "1", "IMAGE_FILE_RELOCS_STRIPPED" },
            new[] { "2", "IMAGE_FILE_EXECUTABLE_IMAGE" },
            new[] { "4", "IMAGE_FILE_LINE_NUMS_STRIPPED" },
            new[] { "8", "IMAGE_FILE_LOCAL_SYMS_STRIPPED" },
            new[] { "16", "IMAGE_FILE_AGGRESIVE_WS_TRIM" },
            new[] { "32", "IMAGE_FILE_LARGE_ADDRESS_AWARE" },
            new[] { "128", "IMAGE_FILE_BYTES_REVERSED_LO" },
            new[] { "256", "IMAGE_FILE_32BIT_MACHINE" },
            new[] { "512", "IMAGE_FILE_DEBUG_STRIPPED" },
            new[] { "1024", "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" },
            new[] { "2048", "IMAGE_FILE_NET_RUN_FROM_SWAP" },
            new[] { "4096", "IMAGE_FILE_SYSTEM" },
            new[] { "8192", "IMAGE_FILE_DLL" },
            new[] { "16384", "IMAGE_FILE_UP_SYSTEM_ONLY" },
            new[] { "32768", "IMAGE_FILE_BYTES_REVERSED_HI" },

            };

        }

        public static string[][] OPTIONAL_HEADER_NAMES()
        {
            return new string[][]
            {
            new[] { "Magic", "Magic" },
            new[] { "MajorLinkerVersion", "Major Linker Version" },
            new[] { "MinorLinkerVersion", "Minor Linker Version" },
            new[] { "SizeOfCode", "Size of Code" },
            new[] { "SizeOfInitializedData", "Size of Initialized Data" },
            new[] { "SizeOfUninitializedData", "Size of Uninitialized Data" },
            new[] { "AddressOfEntryPoint", "Address of Entry Point" },
            new[] { "BaseOfCode", "Base of Code" },
            new[] { "BaseOfData", "Base of Data" },
            new[] { "ImageBase", "Image Base" },
            new[] { "SectionAlignment", "Section Alignment" },
            new[] { "FileAlignment", "File Alignment" },
            new[] { "MajorOperatingSystemVersion", "Major Operating System Version" },
            new[] { "MinorOperatingSystemVersion", "Minor Operating System Version" },
            new[] { "MajorImageVersion", "Major Image Version" },
            new[] { "MinorImageVersion", "Minor Image Version" },
            new[] { "MajorSubsystemVersion", "Major Subsystem Version" },
            new[] { "MinorSubsystemVersion", "Minor Subsystem Version" },
            new[] { "Win32VersionValue", "Win32 Version Value" },
            new[] { "SizeOfImage", "Size of Image" },
            new[] { "SizeOfHeaders", "Size of Headers" },
            new[] { "CheckSum", "Checksum" },
            new[] { "Subsystem", "Subsystem" },
            new[] { "DllCharacteristics", "DllCharacteristics" },
            new[] { "SizeOfStackReserve", "Size of Stack Reserve" },
            new[] { "SizeOfStackCommit", "Size of Stack Commit" },
            new[] { "SizeOfHeapReserve", "Size of Heap Reserve" },
            new[] { "SizeOfHeapCommit", "Size of Heap Commit" },
            new[] { "NumberOfRvaAndSizes", "Number of Data Directories" }
            };
        }

        public static string[][] DLL_CHARACTERISTIC_NAMES_AND_VALUES()
        {
            return new string[][]
            {
            new[] { "0x0040", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" },
            new[] { "0x0080", "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" },
            new[] { "0x0100", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT" },
            new[] { "0x0200", "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION" },
            new[] { "0x0400", "IMAGE_DLLCHARACTERISTICS_NO_SEH" },
            new[] { "0x0800", "IMAGE_DLLCHARACTERISTICS_NO_BIND" },
            new[] { "0x2000", "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER" },
            new[] { "0x8000", "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE" }
            };

        }

    }
}
