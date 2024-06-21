using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class FileHeader
    {
        public StructureDosHeader1 NumberOfSections { get; set; }
        public StructureDosHeader2 TimeDateStamp { get; set; }
        public StructureDosHeader1 PointerToSymbolTable { get; set; }
        public StructureDosHeader1 NumberOfSymbols { get; set; }
        public StructureDosHeader1 Machine { get; set; }
        public StructureDosHeader1 Characteristics { get; set; }
        public StructureDosHeader1 SizeOfOptionalHeader { get; set; }
        public string Structure { get; set; }
    }

}
