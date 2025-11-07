# frontend.py (continuare și finalizare)
import tkinter as tk
from tkinter import messagebox
import threading
import queue
import json
import os
from pathlib import Path

from components import ChallengeListFrame, ScoreboardFrame, ChallengeViewFrame
import utils

DEMO_FILE = Path(__file__).parent / "demo_data.json"

class App:
    def __init__(self, root):
        self.root = root
        root.title("CTF Frontend (Tkinter)")
        self.q = queue.Queue()

        # layout frames
        left = tk.Frame(root)
        left.pack(side="left", fill="y", padx=10, pady=10)
        center = tk.Frame(root)
        center.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        right = tk.Frame(root)
        right.pack(side="right", fill="y", padx=10, pady=10)

        # components
        self.chlist = ChallengeListFrame(left, on_open_cb=self.open_challenge)
        self.chlist.pack(fill="both", expand=True)
        self.score = ScoreboardFrame(right)
        self.score.pack(fill="both", expand=True)
        self.chview = ChallengeViewFrame(center, submit_cb=utils.submit_flag)
        self.chview.pack(fill="both", expand=True)

        # load demo fallback
        self.demo_data = self.load_demo_data()

        # init WS manager
        self.ws_mgr = utils.WSManager(self.q)
        self.ws_mgr.start()

        # start update loop
        self.root.after(100, self.update_loop)

        # initial fetch
        threading.Thread(target=self.fetch_initial_data, daemon=True).start()

    def load_demo_data(self):
        if DEMO_FILE.exists():
            with open(DEMO_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"challenges": [], "scoreboard": []}

    def fetch_initial_data(self):
        ch = utils.fetch_challenges()
        sb = utils.fetch_scoreboard()
        # fallback demo
        if not ch:
            ch = self.demo_data.get("challenges", [])
        if not sb:
            sb = self.demo_data.get("scoreboard", [])
        self.q.put(("init_data", {"challenges": ch, "scoreboard": sb}))

    def update_loop(self):
        try:
            while True:
                item = self.q.get_nowait()
                self.handle_queue(item)
        except queue.Empty:
            pass
        self.root.after(100, self.update_loop)

    def handle_queue(self, item):
        evt, data = item
        if evt == "init_data":
            self.chlist.set_challenges(data.get("challenges", []))
            self.score.set_scoreboard(data.get("scoreboard", []))
        elif evt == "ws_msg":
            msg_type = data.get("type")
            payload = data.get("payload")
            if msg_type == "scoreboard_update":
                self.score.set_scoreboard(payload)
            elif msg_type == "challenge_update":
                self.chlist.set_challenges(payload)
        elif evt == "ws_err":
            print("WS error:", data)
        elif evt == "ws_close":
            print("WS closed:", data)
        elif evt == "ws_open":
            print("WS connected")

    def open_challenge(self, ch):
        self.chview.show_challenge(ch)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
