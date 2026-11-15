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
parser.add_argument('--allow-experimental-features', action='store_true', help='Acknowledge that network-only NSL-KDD features are not validated live protection')
parser.add_argument('--simulate',action='store_true',help='Generate sample features instead of capturing packets')
args=parser.parse_args()
if not args.simulate and not args.allow_experimental_features:
    raise SystemExit('Live flow classification is experimental. Validate authorized captures first, or explicitly pass --allow-experimental-features.')
if os.getenv('IDS_AUTO_ENCRYPT','false').lower() == 'true':
    raise SystemExit('Automatic sensor encryption is disabled. Use the authenticated customer-scoped Files workflow.')
from worker.tasks import start_network_monitor_task
start_network_monitor_task.run(interface=args.interface,simulate=args.simulate)
print('Monitor running; Ctrl+C to stop. File changes require authenticated workspace actions.')
try:threading.Event().wait()
except KeyboardInterrupt:pass
