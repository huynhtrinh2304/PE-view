using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEview
{
    public class DosHeader
    {
        public StructureDosHeader1 e_cblp { get; set; }
        public StructureDosHeader1 e_crlc { get; set; }
        public StructureDosHeader1 e_ovno { get; set; }
        public StructureDosHeader1 e_minalloc { get; set; }
        public StructureDosHeader1 e_csum { get; set; }
        public StructureDosHeader1 e_cparhdr { get; set; }
        public StructureDosHeader1 e_cp { get; set; }
        public StructureDosHeader1 e_cs { get; set; }
        public StructureDosHeader1 e_maxalloc { get; set; }
        public StructureDosHeader1 e_lfarlc { get; set; }
        public StructureDosHeader1 e_oemid { get; set; }
        public StructureDosHeader1 e_lfanew { get; set; }
        public StructureDosHeader1 e_ss { get; set; }
        public StructureDosHeader1 e_magic { get; set; }
        public StructureDosHeader1 e_oeminfo { get; set; }
        public StructureDosHeader2 e_res2 { get; set; }
        public StructureDosHeader2 e_res { get; set; }
        public StructureDosHeader1 e_sp { get; set; }
        public StructureDosHeader1 e_ip { get; set; }
        public string Structure { get; set; }

    }

    public class StructureDosHeader1
    {
        public int FileOffset { get; set; }
        public int Value { get; set; }
        public int Offset { get; set; }
    }
    public class StructureDosHeader2
    {
        public int FileOffset { get; set; }
        public string Value { get; set; }
        public int Offset { get; set; }
    }


}
