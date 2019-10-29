import os
from tkinter.filedialog import askdirectory
import socket
from multiprocessing import Process, Queue
import time
from threading import Thread
import tkinter

def scan_dir():
    basepath = askdirectory()
    for dir in os.listdir(basepath):
        if os.path.isdir(os.path.join(basepath, dir)):
            tkinter.Label(window, text=f"Folder: {dir}").pack()
            #print(f"Directory: {dir}")

    with os.scandir(basepath) as entries:
        for file in entries:
            if file.is_file():
                tkinter.Label(window, text=f"File: {file.name}").pack()
                #print(f"File: {file.name}")
                #file_list.append(file.name)


window = tkinter.Tk()
window.title("The P2P Mayflower")

#tkinter.Label(window, text="IP address").grid(row=0)
#tkinter.Entry(window).grid(row=0, column=1)

tkinter.Button(window, text="Select directory", command=scan_dir).pack()

window.mainloop()
