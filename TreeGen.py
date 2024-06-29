"""
    Title:      TreeGen
    Desc:       Attack Tree Generator Tool enriched with MITRE
    Author:     Adithya Chandra
    LinkedIn    https://www.linkedin.com/in/adithyachandra/
"""


import json
from pyvis.network import Network
from pyattck import Attck
import time
import threading
import argparse
import requests


def main():
    parser = argparse.ArgumentParser(description="TreeGen - Attack Tree Generator")
    parser.add_argument('-f', '--file', metavar='FILE', type=str, required=True,
                        help='JSON file to read')
    parser.add_argument('--version', action='version', version='%(prog)s 1.1',
                        help='Show program\'s version number and exit')
                        
    args = parser.parse_args()
    if args.file:
        try:
            with open(args.file, 'r') as f:
                data = json.load(f)
                #print("Contents of JSON file:")
                #print(json.dumps(data, indent=4))
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.")
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format in '{args.file}': {e}")
            


    net = Network(
    height='750px',
    width='1500px',
    notebook=True,
    bgcolor='#bcbcbc',
    font_color='#111',
    cdn_resources='remote',
    directed=True
    )


    o1 = """
    var options = {
    "nodes": {
    "font": {
      "size": 15
    },
    "shadow": {
      "enabled": true,
      "color": "rgba(0,0,0,0.7)",
      "size": 4,
      "x": 4,
      "y": 4
    }
    },
    "edges": {
    "color": {
      "inherit": true
    },
    "font": {
      "size": 44
    },
    "smooth": {
      "type": "continuous",
      "forceDirection": "none"
    }
    },
    "physics": {
    "barnesHut": {
      "gravitationalConstant": -200,
      "centralGravity": 0
    },
    "minVelocity": 0.75
    }
    }
    """
    net.set_options(o1)
    print("Downloading MITRE Data & analysing \n Please Wait...")
    attack = Attck(enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    def read_func():
        ramanan = attack.enterprise.techniques
        return ramanan
    
    #ProgressBar 
    def progress_bar(stop_event):
        #start_time = time.time()
        while not stop_event.is_set():
              #elapsed_time = time.time() - start_time
              for i in range(100):
                  progress = "#" * (i + 1)
                  remaining = " " * (100 - len(progress))
                  print("\r[{}{}]".format(progress, remaining), end="", flush=True)
                  time.sleep(1)
                  #progress = min(int((elapsed_time / duration) * 100), 100)
                  #remaining = 100 - progress
                  #print("\r[{}{}]".format("#" * progress, " " * remaining), end="", flush=True)
                  #if progress >= 100:
              break
    stop_event = threading.Event()
    progress_thread = threading.Thread(target=progress_bar, args=(stop_event,))
    progress_thread.start()
    ramanan = read_func()
    stop_event.set()
    progress_thread.join()

    graph = Network(height="100px", width="100%")
    added_nodes = set()


    #masterlist for order of tactics
    tactics_order= [
         "reconnaissance",
         "resource-development",
         "initial-access",
         "execution",
         "persistence",
         "privilege-escalation",  
         "defense-evasion",
         "credential-access", 
         "discovery",  
         "lateral-movement",   
         "collection",   
         "command-and-control", 
         "exfiltration",  
         "impact"
        ]

    #fetching tactics from .json
    tactics=[]
    for tech in data['techniques']:
        tact  = tech["tactic"]
        tactics.append(tact)
    tactics = set(tactics)

    #sorting tactics(fetched from json) according to tactics_order-master list 
    tacticlist=[]
    for t in tactics_order:
        if t in tactics:
                tacticlist.append(t)

    added_nodes = set()
    tech = data['techniques'] #data inside set techniques[]
    #for tech in data['techniques']:


    for i in range(len(data['techniques'])):
      technique_id = tech[i]["techniqueID"]
      tactic       = tech[i]["tactic"]
      comment      = tech[i]["comment"]
      metadata   =   tech[i]["metadata"]
      comment      = tech[i]["comment"]
      for technique in ramanan:
                      #print(technique)
                      if technique.technique_id == technique_id:
                                    tname = technique.name
      if tactic not in added_nodes:

            #adding 't values' to each tactics  for connection order
            # tactics fetch> tacticts order> naming t0, t1
            tactdict={}                
            for tactics in tacticlist:
                index = str(tacticlist.index(tactics))
                t = 't'+ index
                tactdict.update({tactics:t}) #key-value pairs with tactic and its 't value'
                net.add_node(tactics, label=tactics, color='#0A82EF' )
                net.add_node('comment', label=comment, color='#000', physics=True, level=0, mass=15)
    
            net.add_node(technique_id, label=technique_id, color='#F55', size=15, mass=10)
            net.add_node(tname, label=tname,physics=True, color='#8fce00', level=1, mass=5, size=9)
            net.add_node(comment, label=comment,physics=True, color='#6a329f', level=1, mass=3, size=5)
            net.add_edge(technique_id,tname)
            net.add_edge(tname, comment)
            net.add_edge('comment',tacticlist[0],width=3, arrows='comment')
            keyslist = list(tactdict.keys())
            for key in range(len(keyslist)-1):
                        curkey = keyslist[key]
                        nextkey = keyslist[key+1]
                        net.add_edge(curkey,nextkey,width=3)

            net.add_edge(tactic, technique_id)
           

    print("\n Result saved in below file:")            
    net.show("attackpath.html")
    
if __name__ == "__main__":
    main()