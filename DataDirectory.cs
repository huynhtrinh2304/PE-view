using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class DataDirectory
    {
        public StructureDosHeader1 VirtualAddress { get; set; }
        public string Structure {  get; set; }
        public StructureDosHeader1 Size { get; set; }

    }
}
