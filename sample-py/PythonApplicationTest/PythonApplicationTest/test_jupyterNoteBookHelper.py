import unittest
#1
#import Pyserva
#from Pyserva import JupyterNotebookHelper as Senserva

#2
#import sys
#sys.path.append('C:\\Users\\Administrator\\Source\\Repos\\Senserva-LLC\\Pyserva\\src\\Pyserva')
#import JupyterNotebookHelper as test

#3
import importlib.util

class Test_test_jupyterNoteBookHelper(unittest.TestCase):
    def test_read_config_values(self):
        spec = importlib.util.spec_from_file_location("jupyterNoteBookHelper",
                                                      "C:\\Users\\Administrator\\Source\\Repos\\Senserva-LLC\\Pyserva\\src\\PyservajupyterNoteBookHelper.py")
        test = importlib.util.module_from_spec(spec)

        try:           
            rtn = test.read_config_values()
        except Exception:        
            pass  
     

if __name__ == '__main__':
    unittest.main()
