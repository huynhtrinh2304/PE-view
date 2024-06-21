using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class SectionHeader
    {
        public ValueFileOffset PointerToRawData { get; set; }
        public string SHA1 { get; set; }
        public string SHA256 { get; set; }
        public Name Name { get; set; }
        public ValueFileOffset NumberOfRelocations { get; set; }
        public ValueFileOffset Misc_VirtualSize { get; set; }
        public Characteristics Characteristics { get; set; }
        public ValueFileOffset Misc { get; set; }
        public ValueFileOffset PointerToLinenumbers { get; set; }
        public ValueFileOffset SizeOfRawData { get; set; }
        public ValueFileOffset Misc_PhysicalAddress { get; set; } 
        public ValueFileOffset PointerToRelocations { get; set; }
        public List<string> Flags { get; set; }
        public string SHA512 { get; set; }
        public string MD5 { get; set; }
        public double Entropy { get; set; }
        public ValueFileOffset VirtualAddress { get; set; }
        public string Structure { get; set; }
        public ValueFileOffset NumberOfLinenumbers { get; set; }
    }

    public class ValueFileOffset
    {
        public int FileOffset { get; set; }
        public int Value { get; set; }
        public int Offset { get; set; }
    }

    public class Name
    {
        public long FileOffset { get; set; }
        public string Value { get; set; }
        public int Offset { get; set; }
    }
    public class Characteristics
    {
        public int FileOffset { get; set; }
        public long Value { get; set; }
        public int Offset { get; set; }
    }


}
