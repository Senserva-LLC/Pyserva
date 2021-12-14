
# Pyserva

The Senserva Python Library is provided to help analyze and visualize data. The JupyterNotebookHelper module will assist users who are utilizing Jupyter Notebooks for their needs. The StandAloneApiHelper will be useful for those who want a pure Python experience. Our team has also made a sample report for Azure Connections, using the StandAloneApiHelper, which will automate the acquisition of data and building the report.

# Install

The Pyserva library is available on the [Python Package Index](https://pypi.org/project/Pyserva/).

The install command on Windows for the package is:

    py -m pip install Pyserva

The install command on Unix/Mac for the package is:

    python3 -m pip install "Pyserva"

  
  The import commands for the library and modules are:
  

    import Pyserva
    from Pyserva import JupyterNotebookHelper
    from Pyserva import StandAloneApiHelper
    from Pyserva import SampleReport

# Modules

### JupyterNotebookHelper
This module will focus on helping a user with visualizing [Senserva data](https://azuremarketplace.microsoft.com/marketplace/apps/senservallc.senserva_multitenant?tab=Overview) in a Jupyter Notebook. 

### StandAloneApiHelper
This module will focus on helping a user with visualizing data from the Microsoft Graph API.

### SampleReport
This module is a Python Command Line app, leveraging the StandAloneApiHelper for data.

# Support

Please reach to our team of experts [via email](mailto:support@senserva.com) for questions regarding the library
