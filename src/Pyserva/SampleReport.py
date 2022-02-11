# Load Python libraries that will be used in this notebook to fetch Azure Sentinel data
from azure.loganalytics.models import QueryBody
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.loganalytics import LogAnalyticsDataClient

# Processing Helpers
import StandaloneApiHelper as SenservaApi

from IPython.display import display, HTML, Markdown
import csv
import pandas as pd
import requests
import webbrowser

# Globals
# We use a file for data set storage so that we only have to grab once
defaultFilter = '(no filter applied)'
filename = 'edge_data_api.csv'
dropdown = [defaultFilter]

import io
import json
import csv
import sys
import pandas as pd
import ipywidgets
import numpy as np
import matplotlib_inline
import matplotlib as map
import matplotlib.image as mpimg
from bokeh.plotting import figure
from bokeh.resources import CDN
from bokeh.embed import file_html

import tkinter as tk
from tkinter import messagebox
from tkinter import *
from urllib.request import urlopen

def main():

    print('''Senserva Python Graph via API  Copyright (C) 2022  Senserva LLC
    This program comes with ABSOLUTELY NO WARRANTY; 
    This is free software, and is provided AS IS; ''')


    authenticated = False
    master = tk.Tk()
    master.title(string="Senserva Connections Scan")

    URL = "https://github.com/Senserva-LLC/SenservaResources/blob/main/HTMLResources/SSL-Symbol-60x60--Green.png?raw=true"
    u = urlopen(URL)
    raw_data = u.read()
    u.close()

    master.tk.call('wm', 'iconphoto', master._w, tk.PhotoImage(data=raw_data))

    frame1 = tk.Frame(master)
    frame2 = tk.Frame(master)
    frame3 = tk.Frame(master)
    
    while not authenticated:
        
        # Need to do the link first, packing after applying grid management is not available
        label = Label(frame2, text="Senserva PowerShell script", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda e: webbrowser.open_new_tab("https://github.com/Senserva-LLC/SenservaForSentinelSetup"))

        tk.Label(frame1, text="Welcome to the Senserva Connections Scan! This standalone scanner will scan your network and build a report for you.").grid(row=0)
        tk.Label(frame1, text="This report builder uses an Azure AD Application ID and Secret to get its dataset.").grid(row=1)
        tk.Label(frame1, text="You can use the script built by our team to create this App or create your own.").grid(row=2)

        tk.Label(frame3, text="Tenant ID").grid(row=2, sticky=tk.W)
        tk.Label(frame3, text="Application ID").grid(row=3, sticky=tk.W)
        tk.Label(frame3, text="Application Secret").grid(row=4, sticky=tk.W)
    
        e1 = tk.Entry(frame3, width=100)
        e2 = tk.Entry(frame3, width=100)
        e3 = tk.Entry(frame3, width=100)
    
        e1.grid(row=2, column=1)
        e2.grid(row=3, column=1)
        e3.grid(row=4, column=1)

        tk.Button(frame3, 
                    text='Continue to the Scan', 
                    command=master.quit).grid(row=6, 
                                            column=0, 
                                            sticky=tk.E, 
                                            pady=4)

        frame1.pack(padx=3, pady=3)
        frame2.pack(padx=3, pady=3)
        frame3.pack(padx=3, pady=3)

        master.mainloop()
   
        try: 
            SenservaApi.authenticate(e1.get(), e2.get(), e3.get()) 
            authenticated = True
            master.quit()
        except tk.TclError as tclErr:
            master.quit()
            authenticated = True
            return
        except Exception as e:
            master.quit()
            tk.messagebox.showerror(title="Error", message="There was a problem getting authentication with the given information. Please check values and try again\n\n" + str(e))
        
    
    print("Getting Service Principal data...")
    spDict = SenservaApi.servicePrincipalsOwners()
    
    print("Getting Application data...")
    appOwnersDict = SenservaApi.applicationsOwners()
    
    print("Getting Role data...")
    rolesMembersDict = SenservaApi.rolesMembers()
    
    print("Getting User data...")
    userMembers = SenservaApi.usersMemberships()
    userManagers = SenservaApi.usersManagers()
    
    print("Getting Group data...")
    groupsMembersDict = SenservaApi.groupsMemberships()
    groupsOwnersDict = SenservaApi.groupsOwners()

    with open(filename, 'w', newline='') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',',
                        quotechar='|', quoting=csv.QUOTE_MINIMAL)
        
        print("Processing data...")

        # Pull out data from the Graph queries
        SenservaApi.PluckDataFromQueryResults(userMembers, userManagers, groupsOwnersDict, groupsMembersDict, rolesMembersDict, appOwnersDict, spDict, filewriter) 
        
        print("Processing complete!")

        items = []

    with open(filename, newline='') as csvfile:
        file_df = pd.read_csv(csvfile,delimiter=',')

        
        print("Rendering data...")
        
        # Render our data as a Graph
        graphPlot = SenservaApi.RenderGraphData(file_df)
        graphHtml = file_html(graphPlot, CDN, "my plot")

        # Render our data as a Table
        items = SenservaApi.filterDataFrameAndCreateList(dropdown, file_df, defaultFilter)
        inputData = SenservaApi.htmlTreeParser(items)
        tableHtml = SenservaApi.getTreeTemplate().format(inputData = inputData)
        
        print("Rendering complete!")
 
        html = SenservaApi.getReportTemplate().format(table_input=tableHtml, graph_input=graphHtml)

        f = open('SenservaReport.html','w')
        f.write(html)
        f.close()
        webbrowser.open_new_tab('SenservaReport.html')

    print("Complete!")

main()
