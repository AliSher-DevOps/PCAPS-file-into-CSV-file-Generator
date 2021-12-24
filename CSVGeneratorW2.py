import subprocess
import datetime
import pandas as pd
import os
import csv

def read_pcap(filename, fields=[], display_filter="", timeseries=False, strict=False):
    if timeseries:
        fields = ["frame.time_epoch"] + fields
    
    fieldspec = " ".join("-e %s" % f for f in fields)
    display_filters = fields if strict else []
    
    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-R '%s'" % " and ".join(f for f in display_filters)

    options = "-r %s -2 -T fields -Eheader=y" % filename
    cmd = "tshark %s %s" % (options, fieldspec)
    proc = subprocess.Popen(cmd, shell = True, stdout=subprocess.PIPE)
    df = pd.read_table(proc.stdout)
    return df

def _replaceitem(x):
    if x < 4:
        return 0
    
    else:
        return x


dir_path = r"D:\New folder (2)"
os.chdir(dir_path)
filename = r"C:\Users\92344\Desktop\files\IPs.csv"

data = pd.read_csv(filename)
pcapFile=data.iloc[:,0].values
pcapIP=data.iloc[:,2].values
multiple=data.iloc[:,4].values
counter=0 


with open("C:\\Users\\92344\Desktop\\Graphs Data\\csvFiles\\Non_VPN_PCAPs_120s_PPS.csv", "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
   
    dir_path =  r"D:\New folder (2)"
    fields=["ip.src", "ip.dst", "ip.proto","frame.len"]
    filelist=os.listdir(dir_path)
    for file in pcapFile:        
        filepath=dir_path +"\\"+file
        print(filepath)    
        
        temp=read_pcap(file, fields, timeseries=True, strict=True)
        temp["frame.time_epoch"]=pd.to_datetime(temp["frame.time_epoch"],unit='s')
         
        IP = str(pcapIP[counter])
        source_address=temp[temp["ip.dst"] == str(IP)]        
        bytes_per_second=source_address.resample("s", on='frame.time_epoch').sum()
        
        lmt = multiple[counter]
        x = 0
        
        for i in range(lmt): 
            
            BPS_list=bytes_per_second['frame.len'][x + 1: x + 120]
            x += 120
            BPS_list = list(map(_replaceitem, BPS_list))
            lenBPS = len(BPS_list)
            if lenBPS < 120:
                print("len is less")
                diff = 120 - lenBPS
                for d in range(diff):
                    BPS_list.append(0)
            print(BPS_list)
            BPS_list.append(file)
            writer.writerow(BPS_list)
        counter+=1