"""Run the packet feature extractor and trained detector on an operator-selected interface."""
import argparse
import os
import sys
import threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'legacy'))
parser=argparse.ArgumentParser()
parser.add_argument('--interface',required=True)
parser.add_argument('--simulate',action='store_true',help='Generate sample features instead of capturing packets')
args=parser.parse_args()
if args.simulate and os.getenv('IDS_AUTO_ENCRYPT','false').lower()=='true':
    raise SystemExit('Disable IDS_AUTO_ENCRYPT before running a simulation')
from worker.tasks import start_network_monitor_task
start_network_monitor_task.run(interface=args.interface,simulate=args.simulate)
print('Monitor running; Ctrl+C to stop. Automatic encryption is off unless explicitly configured.')
try:threading.Event().wait()
except KeyboardInterrupt:pass
