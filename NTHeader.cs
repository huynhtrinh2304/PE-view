using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class NTHeader
    {
        public string Structure {  get; set; }
        public StructureDosHeader1 Signature { get; set; }

    }
}
