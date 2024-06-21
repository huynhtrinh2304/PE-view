using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class OptionalHeader
    {
        public StructureDosHeader1 DllCharacteristics { get; set; }
        public StructureDosHeader1 BaseOfCode { get; set; }
        public StructureDosHeader1 MajorLinkerVersion { get; set; }
        public StructureDosHeader1 MinorOperatingSystemVersion { get; set; }
        public StructureDosHeader1 MinorLinkerVersion { get; set; }
        public StructureDosHeader1 MajorSubsystemVersion { get; set; }
        public StructureDosHeader1 MajorOperatingSystemVersion { get; set; }
        public StructureDosHeader1 SizeOfStackCommit { get; set; }
        public StructureDosHeader1 SizeOfUninitializedData { get; set; }
        public StructureDosHeader1 NumberOfRvaAndSizes { get; set; }
        public StructureDosHeader1 SizeOfHeapReserve { get; set; }
        public StructureDosHeader1 LoaderFlags { get; set; }
        public StructureDosHeader1 SizeOfHeapCommit { get; set; }
        public StructureDosHeader1 SizeOfStackReserve { get; set; }
        public StructureDosHeader1 SizeOfHeaders { get; set; }
        public StructureDosHeader1 Subsystem { get; set; }
        public StructureDosHeader1 Magic { get; set; }
        public StructureDosHeader1 MinorImageVersion { get; set; }
        public StructureDosHeader1 MajorImageVersion { get; set; }
        public StructureDosHeader1 FileAlignment { get; set; }
        public StructureDosHeader1 BaseOfData { get; set; }
        public StructureDosHeader1 AddressOfEntryPoint { get; set; }
        public StructureDosHeader1 SectionAlignment { get; set; }
        public StructureDosHeader1 SizeOfCode { get; set; }
        public StructureDosHeader1 ImageBase { get; set; }
        public StructureDosHeader1 SizeOfInitializedData { get; set; }
        public StructureDosHeader1 SizeOfImage { get; set; }
        public StructureDosHeader1 MinorSubsystemVersion { get; set; }
        public StructureDosHeader1 CheckSum { get; set; }
        public StructureDosHeader1 Reserved1 { get; set; }
        public string Structure { get; set; }

    }
}
