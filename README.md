# TreeGen
🕵️‍♂️ The tool to visualize your detection engineering strategies!



# Pre Requisites:

🔸Python Version: python 3.x

🔸Install all dependencies from the requirements.txt file. 

    pip install -r requirements.txt

🔸Python Libraries Used:
1) pyattck
2) pyvis
3) threading
4) argprase
5) requests
6) json
   
🔸File (Input):
json format file (create/customize using MITRE Navigator)


# How to Run?

Step 1) Map your TTP's using MITRE Navigator : https://mitre-attack.github.io/attack-navigator/

Step 2) Download/ Export the TTP's to json format from the MITRE Navigator

Step 3) Input the Json to the TreeGen script to create Graphical Visualizations
      
      python TreeGen.py -f <filename.json>

    
      
