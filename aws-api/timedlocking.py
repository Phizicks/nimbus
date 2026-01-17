import time
import threading
import logging

class TimedLock:
    _logging = True
    def __init__(self, warn_threshold=1.0):
        self._lock = threading.Lock()
        self.warn_threshold = warn_threshold

    def __call__(self, name, logInfo=True):
        self._logging = logInfo
        """Allow calling the lock with a name: with lock('operation_name'):"""
        return self._TimedLockContext(self, name, logInfo)

    class _TimedLockContext:
        def __init__(self, parent, name, logInfo=True):
            self.parent = parent
            self.name = name
            self._logging = logInfo
            self._start = None
            self._lock = threading.Lock()

        def __enter__(self):
            start = time.monotonic()
            acquired = self.parent._lock.acquire(timeout=30)
            duration = time.monotonic() - start

            if not acquired:
                logging.error(f"[{self.name}] Lock acquisition timeout after 30s!")
                raise TimeoutError(f"Lock {self.name} blocked >30s")
            elif duration > self.parent.warn_threshold:
                logging.warning(f"[{self.name}] Lock took {duration:.2f}s to acquire")
            # else:
            #     logging.debug(f"[{self.name}] Lock acquired in {duration:.2f}s")

            self._start = time.monotonic()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.monotonic() - self._start
            if duration > self.parent.warn_threshold:
                logging.warning(f"[{self.name}] Lock held for {duration:.2f}s")
            # elif self._logging:
            #     logging.debug(f"[{self.name}] Lock held for {duration:.2f}s")
            self.parent._lock.release()
