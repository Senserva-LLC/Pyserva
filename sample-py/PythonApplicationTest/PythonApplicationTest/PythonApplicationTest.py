"""import Pyserva
from Pyserva import JupyterNotebookHelper as Senserva"""

import sys
sys.path.append('C:\\Users\\Administrator\\Source\\Repos\\Senserva-LLC\\Pyserva\\src\\Pyserva')
import JupyterNotebookHelper as Senserva

rtn = Senserva.has_valid_token()
assert rtn == True, "There is no token return." 
