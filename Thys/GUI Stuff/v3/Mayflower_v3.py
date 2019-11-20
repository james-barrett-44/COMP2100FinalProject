import tkinter as tk
from tkinter import *

"""
The class setup and frame switching is copied from https://www.youtube.com/watch?v=jBUpjijYtCk
"""

DEFAULT_FONT = ("Veranda", 10)
DEFAULT_FONT_LARGE = ("Veranda", 35)

class Mayflower(tk.Tk):
    def __init__(self, *arg, **kwargs):

        tk.Tk.__init__(self, *arg, **kwargs)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0,weight=1)
        container.grid_columnconfigure(0,weight=1)

        self.frames = {}

        for F in (StartPage, MainPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        l_welcome = tk.Label(self, text="Welcome to the Mayflower", font=DEFAULT_FONT_LARGE)
        l_subtitle = tk.Label(self, text="The #1 Peer-2-Peer File Sharing Application", font=DEFAULT_FONT)
        l_welcome.pack()
        l_subtitle.pack()
        b_start = tk.Button(self, text="Start", command=lambda :controller.show_frame(MainPage))
        b_start.pack()


class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        l_mainlabel = tk.Label(self, text="Main window")
        l_mainlabel.pack()
        b_back_to_start = tk.Button(self, text="Back to Welcome Page", command=lambda: controller.show_frame(StartPage))
        b_back_to_start.pack()


if __name__ == '__main__':
    app = Mayflower()
    app.title("The P2P Mayflower v3")
    app.geometry("910x620")
    app.mainloop()

