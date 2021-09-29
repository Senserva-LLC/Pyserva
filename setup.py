from distutils.core import setup
setup(
  name = 'Pyserva',       
  packages = ['Pyserva'],  
  version = '0.1',    
  license='MIT',        # Chose a license from here: https://help.github.com/articles/licensing-a-repository
  description = 'Senserva Python Library',  
  author = 'Thomas Dolan',               
  author_email = 'tj@senserva.com',   
  url = 'https://github.com/Senserva-LLC/Pyserva',  
  download_url = 'https://github.com/Senserva-LLC/Pyserva/archive/refs/tags/v_01.tar.gz',   
  keywords = ['Senserva', 'Azure', 'Jupyter'],  
  install_requires=[           
          'azure-common',
          'azure-loganalytics',
          'azure-mgmt-loganalytics',
          'pandas',
          'ipywidgets',
          'ipython',
          'networkx',
          'requests',
          'bokeh',
      ],
  classifiers=[
    'Development Status :: 3 - Alpha',      # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
    'Intended Audience :: Developers',      
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',   
    'Programming Language :: Python :: 3.8',
  ],
)