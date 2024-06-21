import json
import sys
import pefile

DllCharacteristics = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DllCharacteristics.json"
FILE_HEADER = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\FILE_HEADER.json"
OPTIONAL_HEADER = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\OPTIONAL_HEADER.json"
DOS_HEADER = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DOS_HEADER.json"
NT_HEADERS = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\NT_HEADERS.json"
Flags = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\Flags.json"
PE_Sections = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\PE_Sections.json"
DATA_DIRECTORY = "C:\\Users\\trinhhuynh\\source\\repos\\PEview\\DATA_DIRECTORY.json"

arguments = sys.argv[1]
# arguments = "C:\\Users\\trinhhuynh\\Desktop\\Share\\Chapter_1L\\Lab01-01.exe"

pe = pefile.PE(arguments)
dump_file = pe.dump_dict()


with open(DllCharacteristics, 'w') as outfile:
    json.dump(dump_file.get("DllCharacteristics"), outfile, indent=2)

with open(FILE_HEADER, 'w') as outfile:
    json.dump(dump_file.get("FILE_HEADER"), outfile, indent=2)

with open(OPTIONAL_HEADER, 'w') as outfile:
    json.dump(dump_file.get("OPTIONAL_HEADER"), outfile, indent=2)

with open(DOS_HEADER, 'w') as outfile:
    json.dump(dump_file.get("DOS_HEADER"), outfile, indent=2)

with open(NT_HEADERS, 'w') as outfile:
    json.dump(dump_file.get("NT_HEADERS"), outfile, indent=2)

with open(Flags, 'w') as outfile:
    json.dump(dump_file.get("Flags"), outfile, indent=2)

with open(PE_Sections, 'w') as outfile:
    json.dump(dump_file.get("PE Sections"), outfile, indent=2)

data_directory_arr = [];
for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    data_directory_json = data_directory.dump_dict()
    data_directory_arr.append(data_directory_json)

with open(DATA_DIRECTORY, 'w') as outfile:
    json.dump(data_directory_arr, outfile, indent=2)
