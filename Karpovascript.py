__author__ = 'tanya'
# -*- coding: UTF-8 -*-
#!/usr/bin/python


import os
from os.path import isdir
from os.path import join as joinpath
import pefile
import hashlib
from time import gmtime, strftime
import urllib2
from bs4 import BeautifulSoup
import sys

if len (sys.argv) > 1:
    directory = sys.argv[1]
else:
    print ("Enter directory path: Karpovascript.py disk:\path_to_directory")
    sys.exit()

try:
    files = os.listdir(directory)
except:
    print("Directory not found")
    sys.exit()

errorfilecounter = 0

i = 0
while i < len(files):
     if isdir(joinpath(directory,files[i])):
        del files[i]
     else:
         i+=1


for filename in files:

    try:
        pe = pefile.PE(joinpath(directory,filename))
    except:
        print(filename+" is not a PE file")
        errorfilecounter+=1
        continue

    mypublisher=myproduct=mydescription="null"

    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    if (entry[0] == "CompanyName"):
                        mypublisher = entry[1]
                    if (entry[0] == "ProductName"):
                        myproduct = entry[1]
                    if (entry[0] == "FileDescription"):
                        mydescription = entry[1]

    myMD5 = hashlib.md5(open(joinpath(directory,filename), 'rb').read()).hexdigest()
    mySHA1 = hashlib.sha1(open(joinpath(directory,filename), 'rb').read()).hexdigest()
    mySHA256 = hashlib.sha256(open(joinpath(directory,filename), 'rb').read()).hexdigest()
    mycompilationtimestamp = strftime('%-m/%-d/%Y %-I:%M:%S %p', gmtime(pe.FILE_HEADER.TimeDateStamp))
    myOSversion = str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)+'.'+str(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)

    bitness = int(hex(pe.VS_FIXEDFILEINFO.FileOS), 16)

    if (bitness&0x0000FF == 0x00001):
        myOSbitness = 'Win16'
    elif (bitness&0x0000FF == 0x00004):
        myOSbitness = 'Win32'
    elif (bitness&0x0000FF == 0x00005):
        myOSbitness = 'Win64'
    else:
        myOSbitness = 'Unknown'

    sub = pe.OPTIONAL_HEADER.Subsystem

    if (sub == 2):
        mysubsystem = 'Windows GUI'
    elif (sub == 3):
        mysubsystem = 'Windows Console'
    else:
        mysubsystem = 'Unknown'

    mylinkerversion = str(pe.OPTIONAL_HEADER.MajorLinkerVersion)+'.'+str(pe.OPTIONAL_HEADER.MinorLinkerVersion)

    site = "http://www.herdprotect.com/-"+mySHA1+".aspx"

    hdr = {'User-Agent':'Mozilla', 'Accept': 'html'}
    req = urllib2.Request(site, headers=hdr)
    try:
        page = urllib2.urlopen(req)
    except:
        print(filename+" " + site + " : url is not found")
        errorfilecounter+=1
        continue

    content = page.read()
    page.close()

    soup = BeautifulSoup(content, 'html.parser')

    keyvaluelist = soup.find_all('div', {'class': 'keyvaluepair'})

    i=0
    data_from_herdprotect = dict()
    for keyvalue in keyvaluelist:
        try:
            key = soup.find_all('div', {'class': 'key'})[i].text
        except:
            continue
        value = soup.find_all('div', {'class': 'value'})[i].text
        data_from_herdprotect[key] = value
        i+=1

    errorfields = []

    if (filename != data_from_herdprotect.get('File name:')):
        errorfields.append("File name")
    if (mypublisher != data_from_herdprotect.get('Publisher:')):
        errorfields.append("Publisher")
    if (myproduct != data_from_herdprotect.get('Product:')):
         errorfields.append("Product")
    if (mydescription != data_from_herdprotect.get('Description:')):
        errorfields.append("Description")
    if (myMD5 != data_from_herdprotect.get('MD5:')):
         errorfields.append("MD5")
    if (mySHA1 != data_from_herdprotect.get('SHA-1:')):
         errorfields.append("SHA-1")
    if (mySHA256 != data_from_herdprotect.get('SHA-256:')):
         errorfields.append("SHA-256")
    if (mycompilationtimestamp != data_from_herdprotect.get('Compilation timestamp:')):
         errorfields.append("Compilation timestamp")
    if (myOSversion != data_from_herdprotect.get('OS version:')):
         errorfields.append("OS version")
    if (myOSbitness != data_from_herdprotect.get('OS bitness:')):
         errorfields.append("OS bitness")
    if (mysubsystem != data_from_herdprotect.get('Subsystem:')):
         errorfields.append("Subsystem")
    if (mylinkerversion != data_from_herdprotect.get('Linker version:')):
         errorfields.append("Linker version")

    if(len(errorfields)>0):
        print(filename+" "+site)
        print("Error fields: ")
        print(errorfields)
        errorfilecounter+=1

print( "Number of checked files: " + str(len(files)) + " , number of mismatched files: "+ str(errorfilecounter))