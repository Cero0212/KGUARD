import subprocess
import os
import logging
from datetime import datetime

import psutil

logger = logging.getLogger(__name__)


class ServiceController:
    def __init__(self):
        self._process = None
        self._start_time = None

    def start(self):
        if self.is_running():
            return False
        port = os.environ.get('PORT', '1717')
        self._process = subprocess.Popen(
            ['python', 'app.py'],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._start_time = datetime.now()
        return True

    def stop(self):
        if not self._process:
            return True
        try:
            parent = psutil.Process(self._process.pid)
            for child in parent.children(recursive=True):
                child.terminate()
            parent.terminate()
        except psutil.NoSuchProcess:
            pass
        self._process = None
        self._start_time = None
        return True

    def is_running(self) -> bool:
        return bool(self._process and self._process.poll() is None)

    def get_uptime(self) -> str:
        if self._start_time:
            delta = datetime.now() - self._start_time
            return str(delta).split('.')[0]
        return '0:00:00'
