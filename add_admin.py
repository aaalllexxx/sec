import os
import secrets
try:
    from . import auth
except ImportError:
    import auth

# Helper functions moved to auth.py

def run(base_dir, gconf_path="", args=None):
    project_root = os.getcwd()
    auth.create_admin(project_root)
