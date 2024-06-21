using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.Remoting.Contexts;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using System.IO.Ports;


namespace PEview
{
    public partial class Form1 : Form
    {
        private HexDumpFile hexDumpFile;
        public Form1()
        {
            InitializeComponent();
            hexDumpFile = new HexDumpFile();

        }

        private void fileToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void openToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();

            openFileDialog1.Title = "Chọn File";
            openFileDialog1.Filter = "Các tệp tin|*.dll;*.exe|Tất cả các tệp tin|*.*";

            // lay do dai cua mang data

            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                string filePath = openFileDialog1.FileName;
                hexDumpFile.ExcuteFilePy(filePath);

                TreeNode rootNode = new TreeNode("Program");
                rootNode.Name = filePath;
                treeView1.Nodes.Add(rootNode);

                List<String> namesData = Code.getNameData();
                List<String> listMd5 = Code.getMd5(); 

                TreeNode dos_header = new TreeNode("IMAGE_DOS_HEADER");
                dos_header.Name = "IMAGE_DOS_HEADER";
                rootNode.Nodes.Add(dos_header);

                TreeNode ms_dos_header = new TreeNode("MS_DOS Stub Program");
                ms_dos_header.Name = filePath;
                rootNode.Nodes.Add(ms_dos_header);

                TreeNode img_nt_header = new TreeNode("IMAGE_NT_HEADERS");
                img_nt_header.Name = filePath;
                rootNode.Nodes.Add(img_nt_header);

                TreeNode signatue = new TreeNode("Signature");
                signatue.Name = "signature";
                img_nt_header.Nodes.Add(signatue);

                TreeNode ima_file = new TreeNode("IMAGE_FILE_HEADERS");
                ima_file.Name = "IMAGE_NT_HEADERS";
                img_nt_header.Nodes.Add(ima_file);

                TreeNode img_optional_header = new TreeNode("IMAGE_OPTIONAL_HEADERS");
                img_optional_header.Name = "IMAGE_NT_HEADERS";
                img_nt_header.Nodes.Add(img_optional_header);

                string jsonFilePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json";
                string jsonData = File.ReadAllText(jsonFilePath);
                JArray jArray = JArray.Parse(jsonData);


                for (int i = 0; i < jArray.Count; i++)
                {
                    TreeNode childNode = new TreeNode("IMAGE_SECTION_HEADER " + namesData[i]);
                    childNode.Name = listMd5[i];
                    rootNode.Nodes.Add(childNode);
                }
                for (int i = 0; i < jArray.Count; i++)
                {
                    TreeNode childNode = new TreeNode("SECTION " + namesData[i]);
                    childNode.Name = listMd5[i] + " " + filePath;
                    rootNode.Nodes.Add(childNode);
                }


            }

        }

        private void splitContainer1_Panel1_Paint(object sender, PaintEventArgs e)
        {

        }

        private void splitContainer1_Panel2_Paint(object sender, PaintEventArgs e)
        {
            splitContainer1.BorderStyle = BorderStyle.FixedSingle;

        }

        private void button1_Click(object sender, EventArgs e)
        {

            Code sc = new Code();
            sc.ReadFileHeader();






        }

        private void treeView1_AfterSelect(object sender, TreeViewEventArgs e)
        {
            TreeNode selectedNode = e.Node;

            if (selectedNode.Parent == null)
            {
                
                string data = hexDumpFile.ReadHexDump(selectedNode.Name);
                string[] substrings = data.Split('\n');

                listView1.Clear();

                listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                listView1.Columns.Add("Raw Data", 270, HorizontalAlignment.Left);
                listView1.Columns.Add("Value", 150, HorizontalAlignment.Left);

                foreach (string listData in substrings)
                {

                    if (listData.Length > 0)
                    {
                        string part1 = listData.Substring(0, 9);
                        string part2 = listData.Substring(10, 47);
                        string part3 = listData.Substring(58);
                        ListViewItem item = new ListViewItem(part1);

                        item.SubItems.Add(part2);
                        item.SubItems.Add(part3);
                        listView1.Items.Add(item);
                    }
                }
            }
            else
            {
                listView1.Clear();

                //IMAGE_SECTION_HEADER
                if (selectedNode.Text[6]=='S')
                {
                    Code sc = new Code();

                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Data", 150, HorizontalAlignment.Left);
                    listView1.Columns.Add("Description", 160, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 180, HorizontalAlignment.Left);
                    string slMd5 = "";

                    for (int i = 0; i < Code.getMd5().Count; i++)
                    {
                        if (Code.getMd5()[i] == selectedNode.Name)
                        {
                            slMd5 = Code.getMd5()[i];
                        }
                    }

                    foreach (KeyValuePair<string, List<string>> sectionKvp in sc.ReadSections(slMd5))
                    {
                        ListViewItem item1 = new ListViewItem(sectionKvp.Value[0]);

                        for (int i = 1; i < sectionKvp.Value.Count; i++)
                        {
                            item1.SubItems.Add(sectionKvp.Value[i]);
                        }
                        listView1.Items.Add(item1);
                    }

                }
                
                //SECTION
                else if (selectedNode.Text[1] == 'E')
                {

                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Raw Data", 270, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 150, HorizontalAlignment.Left);


                    List<string> listPathCutted = hexDumpFile.CutPath(selectedNode.Name);


                    List<int> pointData = Code.getDataSection(listPathCutted[0]);

                    string data = hexDumpFile.ReadHexDump(listPathCutted[1], pointData[0], pointData[1]);
                    string[] substrings = data.Split('\n');

                    foreach (string listData in substrings)
                    {

                        if (listData.Length > 0)
                        {
                            string part1 = listData.Substring(0, 9);
                            string part2 = listData.Substring(10, 47);
                            string part3 = listData.Substring(58);
                            ListViewItem item = new ListViewItem(part1);


                            item.SubItems.Add(part2);
                            item.SubItems.Add(part3);
                            listView1.Items.Add(item);
                        }
                    }
                }

                //MS_DOS
                else if (selectedNode.Text[0] == 'M')
                {
                    int a = Code.getDosHeaderData();
                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Raw Data", 270, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 150, HorizontalAlignment.Left);

                    string data = hexDumpFile.ReadHexDump(selectedNode.Name, a, 10*16);
                    string[] substrings = data.Split('\n');


                    foreach (string listData in substrings)
                    {
                        if (listData.Length > 0)
                        {
                            string part1 = listData.Substring(0, 9);
                            string part2 = listData.Substring(10, 47);
                            string part3 = listData.Substring(58);
                            ListViewItem item = new ListViewItem(part1);

                            item.SubItems.Add(part2);
                            item.SubItems.Add(part3);
                            listView1.Items.Add(item);
                        }
                    }

                }

                //IMAGE_DOS_HEADER
                else if ((selectedNode.Text[6] == 'D'))
                {
                    Code code = new Code();
                    List<List<string>> listData = code.ReadDosHeader();
                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Data", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Description", 160, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 180, HorizontalAlignment.Left);

                    foreach (var data in listData)
                    {
                        ListViewItem item = new ListViewItem(data[0]);

                        for (int i = 1; i < data.Count; i++)
                        {
                            item.SubItems.Add(data[i]);
                        }
                        listView1.Items.Add(item);
                    }
                }
                
                //Signature
                else if ((selectedNode.Text[1] == 'i'))
                {
                    Code code = new Code();
                    List<string> signature = code.ReadSignature();
                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Data", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Description", 100, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 180, HorizontalAlignment.Left);

                    ListViewItem item = new ListViewItem(signature[0]);

                    for (int i = 1; i < signature.Count; i++)
                    {
                        item.SubItems.Add(signature[i]);
                    }
                    listView1.Items.Add(item);


                }
               
                //IMAGE_FILE_HEADER
                else if ((selectedNode.Text[6] == 'F'))
                {
                    Code code = new Code();
                    List<List<string>> fileHeader = code.ReadFileHeader();
                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Data", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Description", 140, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 220, HorizontalAlignment.Left);

                    foreach (var value in fileHeader)
                    {
                        ListViewItem item = new ListViewItem(value[0]);
                        for (int i = 1; i < value.Count; i++)
                        {
                            item.SubItems.Add(value[i]);
                        }
                        listView1.Items.Add(item);

                    }





                }

                //IMAGE_OPTIONAL_HEADER
                else if ((selectedNode.Text[6] == 'O'))
                {
                    Code code = new Code();
                    List<List<string>> fileHeader = code.ReadOptionalHeader();
                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Data", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Description", 140, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 240, HorizontalAlignment.Left);

                    foreach (var value in fileHeader)
                    {
                        ListViewItem item = new ListViewItem(value[0]);
                        for (int i = 1; i < value.Count; i++)
                        {
                            item.SubItems.Add(value[i]);
                        }
                        listView1.Items.Add(item);

                    }
                }

                //IMAGE_NT_HEADER
                else if (selectedNode.Text[6] == 'N')
                {

                    listView1.Columns.Add("pFIle", 80, HorizontalAlignment.Left);
                    listView1.Columns.Add("Raw Data", 270, HorizontalAlignment.Left);
                    listView1.Columns.Add("Value", 150, HorizontalAlignment.Left);

                    string filePath = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\NT_HEADERS.json";
                    string json = File.ReadAllText(filePath);

                    NTHeader sectionJsonHeader = JsonConvert.DeserializeObject<NTHeader>(json);

                    string data = hexDumpFile.ReadHexDump(selectedNode.Name, sectionJsonHeader.Signature.FileOffset, 15*16);
                    string[] substrings = data.Split('\n');

                    foreach (string listData in substrings)
                    {

                        if (listData.Length > 0)
                        {
                            string part1 = listData.Substring(0, 9);
                            string part2 = listData.Substring(10, 47);
                            string part3 = listData.Substring(58);
                            ListViewItem item = new ListViewItem(part1);


                            item.SubItems.Add(part2);
                            item.SubItems.Add(part3);
                            listView1.Items.Add(item);
                        }
                    }
                }
            }
        }
    }
}
