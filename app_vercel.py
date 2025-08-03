# app_vercel.py - Vercel-compatible version
# This version disables network monitoring features that require privileged access

import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
import csv
import threading
import time
from datetime import datetime, timedelta
import base64
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score
from sklearn.preprocessing import label_binarize
import joblib
import json

# Import the original app but disable network monitoring
from app import *

# Disable network monitoring for Vercel deployment
def start_ids_monitor_vercel():
    """Vercel-compatible version that doesn't start network monitoring"""
    print("[INFO] Network monitoring disabled for Vercel deployment")
    # Create a mock thread that does nothing
    def mock_monitor():
        while True:
            time.sleep(60)  # Sleep for 1 minute
    thread = threading.Thread(target=mock_monitor, daemon=True)
    thread.start()

# Override the original function
start_ids_monitor = start_ids_monitor_vercel

# Modify the main execution for Vercel
if __name__ == '__main__':
    # Only start simulation in the main process, not the reloader
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        monitor_thread = threading.Thread(target=start_ids_monitor, daemon=True)
        monitor_thread.start()
    
    # Use production settings for Vercel
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False) 