#!/usr/bin/python3
import os
from tkinter.filedialog import askdirectory

basepath = askdirectory()

#basepath = 'C:/Users/nademat/Documents/GitHub/COMP2100FinalProject/Thys'

file_list = []
"""https://realpython.com/working-with-files-in-python"""
for dir in os.listdir(basepath):
    if os.path.isdir(os.path.join(basepath, dir)):
        print(f"Directory: {dir}")

with os.scandir(basepath) as entries:
    for file in entries:
        if file.is_file():
            print(f"File: {file.name}")
            file_list.append(file.name)

#print(file_list)