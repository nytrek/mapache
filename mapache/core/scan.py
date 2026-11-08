"""Single multithreaded scan of a drive, shared by every module."""
import heapq
import os
import queue
import stat
import sys
import threading
import time
from collections import defaultdict

from ..i18n import t
from ..ui.console import B, COLOR, CYN, GRY, R, hs
from .fs import disp, ikey, lp
from .model import BigFile
from .paths import CLOUD_ATTRS, FILE_ATTRIBUTE_REPARSE_POINT, MB, SKIP_TAGS


class DriveScan:
    def __init__(self, root, threads: int = None, big_min: int = 200 * MB, topn: int = 60):
        self.root = lp(root)
        self.n = max(1, threads or min(48, (os.cpu_count() or 4) * 4))
        self.big_min, self.topn = big_min, topn
        self.q = queue.Queue()
        self.own = {}  # folder -> bytes of its direct files
        self.parent = {self.root: None}
        self.denied, self.big = [], []
        self.lock = threading.Lock()
        self.files = [0] * self.n
        self.bytes = [0] * self.n
        self.cloud = [0] * self.n
        self.heaps = [[] for _ in range(self.n)]
        self.exts = [defaultdict(int) for _ in range(self.n)]
        self.total, self.children, self.index = {}, defaultdict(list), {}
        self.elapsed, self.scanned = 0.0, 0

    # --- Walk ---
    def _worker(self, i: int):
        q, own, parent = self.q, self.own, self.parent
        heap, ext, topn, big_min = self.heaps[i], self.exts[i], self.topn, self.big_min
        S_ISDIR, S_ISLNK = stat.S_ISDIR, stat.S_ISLNK
        push, replace = heapq.heappush, heapq.heapreplace
        while True:
            d = q.get()
            if d is None:
                q.task_done()
                return
            total = nfiles = 0
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            st = e.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        mode = st.st_mode
                        if S_ISLNK(mode):
                            continue
                        attrs = getattr(st, "st_file_attributes", 0)
                        if S_ISDIR(mode):
                            if attrs & FILE_ATTRIBUTE_REPARSE_POINT and getattr(st, "st_reparse_tag", 0) in SKIP_TAGS:
                                continue
                            parent[e.path] = d
                            q.put(e.path)
                            continue
                        size = st.st_size
                        if attrs & CLOUD_ATTRS:  # cloud-only files take no disk space
                            self.cloud[i] += size
                            continue
                        total += size
                        nfiles += 1
                        if len(heap) < topn:
                            push(heap, (size, e.path))
                        elif size > heap[0][0]:
                            replace(heap, (size, e.path))
                        if size >= big_min:
                            bf = BigFile(e.path, size, st.st_mtime, getattr(st, "st_birthtime", st.st_ctime))
                            with self.lock:
                                self.big.append(bf)
                        name = e.name
                        dot = name.rfind(".")
                        ext[name[dot + 1:].lower() if dot > 0 else ""] += size
            except OSError:
                with self.lock:
                    self.denied.append(d)
            own[d] = total
            self.bytes[i] += total
            self.files[i] += nfiles
            q.task_done()

    def run(self, progress: bool = True):
        self.q.put(self.root)
        ts = [threading.Thread(target=self._worker, args=(i,), daemon=True) for i in range(self.n)]
        for th in ts:
            th.start()
        t0 = time.perf_counter()
        spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        k = 0
        while self.q.unfinished_tasks:
            if progress and (COLOR or k % 25 == 0):
                sys.stdout.write(
                    f"\r  {CYN}{spin[k % len(spin)]}{R} {t('scan.scanning')} {B}{disp(self.root)}{R}  "
                    f"{sum(self.files):>12,} {t('scan.files')}  {hs(sum(self.bytes)):>10}  "
                    f"{GRY}{time.perf_counter() - t0:5.1f}s{R}   ")
                sys.stdout.flush()
            k += 1
            time.sleep(0.08)
        for _ in ts:
            self.q.put(None)
        for th in ts:
            th.join()
        if progress:
            sys.stdout.write("\r" + " " * 110 + "\r")
        self.elapsed = time.perf_counter() - t0
        self._aggregate()
        return self

    def _aggregate(self):
        total = dict(self.own)
        parent = self.parent
        sep = os.sep
        for p in sorted(total, key=lambda x: x.count(sep), reverse=True):
            par = parent.get(p)
            if par is not None:
                total[par] = total.get(par, 0) + total[p]
        for p, par in parent.items():
            if par is not None and p in total:
                self.children[par].append(p)
        self.total = total
        self.scanned = total.get(self.root, 0)
        self.index = {ikey(p): p for p in total}

    # --- Queries ---
    @property
    def files_count(self) -> int:
        return sum(self.files)

    @property
    def dirs_count(self) -> int:
        return len(self.own)

    @property
    def cloud_bytes(self) -> int:
        return sum(self.cloud)

    def key(self, p):
        return self.index.get(ikey(p))

    def size(self, p):
        """Size of a scanned folder, or None if it is not indexed."""
        k = self.key(p)
        return self.total.get(k) if k else None

    def top_files(self, n: int) -> list:
        return heapq.nlargest(n, [x for h in self.heaps for x in h])

    def ext_totals(self) -> dict:
        merged = defaultdict(int)
        for e in self.exts:
            for k, v in e.items():
                merged[k] += v
        return merged

    def dirs_named(self, name: str) -> list:
        """Folders with this name, excluding ones nested inside another match."""
        name = name.lower()
        out = []
        for k, p in self.index.items():
            base = k.rsplit(os.sep, 1)[-1]
            if base == name and (os.sep + name + os.sep) not in k:
                out.append(p)
        return out
