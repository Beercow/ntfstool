import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os


class NtfstoolWrapperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NTFSTool GUI")
        self.root.geometry("850x700")

        # --- Variables ---
        self.shell_process = None
        self.executable_path = tk.StringVar()
        self.selected_command = tk.StringVar()

        # Parameter variables
        self.params = {
            "disk": tk.StringVar(),
            "volume": tk.StringVar(),
            "inode": tk.StringVar(),
            "output": tk.StringVar(),
            "format": tk.StringVar(),
            "from_path": tk.StringVar(),
            "password": tk.StringVar(),
            "sid": tk.StringVar(),
            "fve_block": tk.StringVar(),
            "rules": tk.StringVar(),
            "masterkey": tk.StringVar(),
            "fvek": tk.StringVar()
        }

        # Definition of commands and their parameters
        self.command_defs = {
            "info":             ["disk", "volume"],
            "mbr":              ["disk"],
            "gpt":              ["disk"],
            "vbr":              ["disk", "volume"],
            "extract":          ["disk", "volume", "inode", "from_path", "output"],
            "image":            ["disk", "volume", "output"],
            "mft.dump":         ["disk", "volume", "output", "format"],
            "mft.record":       ["disk", "volume", "inode"],
            "mft.btree":        ["disk", "volume", "inode"],
            "logfile.dump":     ["disk", "volume", "output", "format"],
            "usn.dump":         ["disk", "volume", "output", "format"],
            "usn.analyze":      ["disk", "volume", "from_path", "rules", "output", "format"],
            "bitlocker.info":   ["disk", "volume", "password"],
            "bitlocker.decrypt":["disk", "volume", "fvek", "output"],
            "bitlocker.fve":    ["disk", "volume", "fve_block"],
            "efs.backup":       ["disk", "volume", "password"],
            "efs.decrypt":      ["disk", "volume", "password", "output"],
            "efs.certificate":  ["disk", "volume", "inode", "output"],
            "efs.key":          ["disk", "volume", "inode", "masterkey", "output"],
            "efs.masterkey":    ["disk", "volume", "inode", "sid", "password"],
            "reparse":          ["disk", "volume"],
            "shadow":           ["disk", "volume"],
            "streams":          ["disk", "volume", "from_path"],
            "undelete":         ["disk", "volume", "inode", "format", "output"],
            "smart":            ["disk"],
            "shell":            ["disk", "volume"]
        }

        self.setup_ui()

    def setup_ui(self):
        # --- Style ---
        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))

        # --- Executable Selection ---
        exe_frame = ttk.LabelFrame(self.root, text="Configuration", padding=(10, 5))
        exe_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(exe_frame, text="NTFSTool Path:").pack(side="left")
        ttk.Entry(exe_frame, textvariable=self.executable_path, width=50).pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(exe_frame, text="Browse...", command=self.browse_exe).pack(side="left")

        # --- Command Selection ---
        cmd_frame = ttk.LabelFrame(self.root, text="Command Selection", padding=(10, 5))
        cmd_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(cmd_frame, text="Select Action:").pack(side="left")

        # Sort commands but ensure "info" is first
        cmd_list = sorted(list(self.command_defs.keys()))
        if "info" in cmd_list:
            cmd_list.insert(0, cmd_list.pop(cmd_list.index("info")))

        self.cmd_cb = ttk.Combobox(cmd_frame, textvariable=self.selected_command, values=cmd_list, state="readonly", width=30)
        self.cmd_cb.pack(side="left", padx=5)
        self.cmd_cb.bind("<<ComboboxSelected>>", self.on_command_change)

        # --- Parameters Area ---
        self.param_frame = ttk.LabelFrame(self.root, text="Parameters", padding=(10, 5))
        self.param_frame.pack(fill="x", padx=10, pady=5)

        self.input_widgets = {}
        ordered_keys = ["disk", "volume", "inode", "output", "format", "from_path", "password", "sid", "fve_block", "rules", "masterkey", "fvek"]
        labels = {
            "disk": "Disk ID (e.g. 0):",
            "volume": "Volume ID (e.g. 1):",
            "inode": "Inode (Dec/Hex):",
            "output": "Output Path:",
            "format": "Format (csv/json/raw):",
            "from_path": "File Path (from=):",
            "password": "Password:",
            "sid": "SID:",
            "fve_block": "FVE Block:",
            "rules": "Rules:",
            "masterkey": "masterkey:",
            "fvek": "fvek:"
        }
        
        BROWSE_FIELDS = {"output", "rules"}

        for key in ordered_keys:
            lbl = ttk.Label(self.param_frame, text=labels[key])
            if key in BROWSE_FIELDS:
                frm = ttk.Frame(self.param_frame)
                ent = ttk.Entry(frm, textvariable=self.params[key], width=30)
                btn = ttk.Button(frm, text="...", width=3, command=lambda k=key: self.browse_output(k))
                self.input_widgets[key] = (lbl, frm, ent, btn)
            #elif key == "rules":
            #    frm = ttk.Frame(self.param_frame)
            #    ent = ttk.Entry(frm, textvariable=self.params[key], width=30)
            #    btn = ttk.Button(frm, text="...", width=3, command=lambda k=key: self.browse_output(k))
            #    self.input_widgets[key] = (lbl, frm, ent, btn)
            else:
                ent = ttk.Entry(self.param_frame, textvariable=self.params[key], width=30)
                self.input_widgets[key] = (lbl, ent)

        # --- Run Button ---
        btn_frame = ttk.Frame(self.root, padding=(10, 5))
        btn_frame.pack(fill="x", padx=10)
        self.run_btn = ttk.Button(btn_frame, text="RUN COMMAND", command=self.start_run_thread)
        self.run_btn.pack(fill="x", pady=5)

        # --- Output Log ---
        out_frame = ttk.LabelFrame(self.root, text="Output / Help", padding=(10, 5))
        out_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(out_frame, height=15, state="disabled", font=("Consolas", 9))
        self.output_text.pack(fill="both", expand=True)
        
        # --- shell cmd ---
        self.shell_frame = ttk.LabelFrame(self.root, text="shell with few commands (help, exit, cd, ls, cat, pwd, cp, quit, rec)")
        self.shell_frame.pack(fill="x", padx=10, pady=5)
        
        self.shell_lbl = ttk.Label(self.shell_frame, text="shell with few commands (help, exit, cd, ls, cat, pwd, cp, quit, rec)")
        self.shell_input = ttk.Entry(self.shell_frame)
        self.shell_input.pack(side="left", fill="x", expand=True)
        
        self.shell_send_btn = ttk.Button(
            self.shell_frame,
            text="Send",
            command=self.send_shell_input
        )
        self.shell_send_btn.pack(side="left", padx=5)
        
        self.shell_frame.pack_forget()  # hidden by default

        # --- Initial State ---
        if "info" in cmd_list:
            self.cmd_cb.current(0)
            self.update_inputs_visibility()

    def browse_exe(self):
        file_path = filedialog.askopenfilename(title="Select NTFSTool Executable", filetypes=[("Executables", "*.exe"), ("All Files", "*.*")])
        if file_path:
            self.executable_path.set(file_path)
            # Trigger help fetch manually since the executable changed
            self.on_command_change(None)

    def browse_output(self, key):
        path = filedialog.asksaveasfilename(title="Select Output File")
        if path:
            self.params[key].set(path)

    def on_command_change(self, event):
        """Called when dropdown changes or manually triggered."""
        self.update_inputs_visibility()

        # Safe Threading: Get values in MAIN thread, pass to WORKER thread
        exe_path = self.executable_path.get()
        cmd_name = self.selected_command.get()

        if exe_path and os.path.exists(exe_path) and cmd_name:
            threading.Thread(target=self.fetch_help_worker, args=(exe_path, cmd_name), daemon=True).start()
        elif not exe_path:
            self.log_safe("Please select the NTFSTool executable above to see command help.")

    def update_inputs_visibility(self):
        # Hide all first
        for key, widgets in self.input_widgets.items():
            if len(widgets) == 2:  # Label, Entry
                widgets[0].grid_forget()
                widgets[1].grid_forget()
            else:  # Label, Frame (Entry+Btn)
                widgets[0].grid_forget()
                widgets[1].grid_forget()
                widgets[2].pack_forget()
                widgets[3].pack_forget()

        cmd = self.selected_command.get()
        if not cmd:
            return

        required_params = self.command_defs.get(cmd, [])

        row = 0
        col = 0
        for i, key in enumerate(required_params):
            if key not in self.input_widgets:
                continue

            widgets = self.input_widgets[key]

            # Label
            widgets[0].grid(row=row, column=col, sticky="w", padx=5, pady=5)

            # Entry/Frame
            if len(widgets) == 2:
                widgets[1].grid(row=row, column=col+1, sticky="w", padx=5, pady=5)
            else:
                widgets[1].grid(row=row, column=col+1, sticky="w", padx=5, pady=5)
                widgets[2].pack(side="left", fill="x", expand=True)
                widgets[3].pack(side="left", padx=2)

            col += 2
            if col > 2:
                col = 0
                row += 1
        
        # Show/hide shell input
        if cmd == "shell":
            self.shell_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.shell_frame.pack_forget()

    def fetch_help_worker(self, exe_path, cmd_name):
        """Worker thread for fetching help. NO TKINTER ACCESS HERE."""
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # Command: ntfstool help [command]
            process = subprocess.Popen(
                [exe_path, "help", cmd_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,  # Prevent hanging if tool asks for input
                text=True,
                startupinfo=startupinfo
            )
            stdout, stderr = process.communicate()

            # Schedule UI update on main thread
            self.root.after(0, self.update_log_window, f"--- HELP: {cmd_name} ---\n{stdout}\n{stderr}")

        except Exception as e:
            self.root.after(0, self.update_log_window, f"Error fetching help: {str(e)}")

    def start_run_thread(self):
        exe_path = self.executable_path.get()
        cmd_name = self.selected_command.get()

        if not exe_path:
            messagebox.showerror("Error", "Please select the NTFSTool executable first.")
            return

        if not cmd_name:
            messagebox.showerror("Error", "Please select a command.")
            return

        # Prepare arguments in main thread
        args = [exe_path, cmd_name]
        required_keys = self.command_defs.get(cmd_name, [])

        for key in required_keys:
            val = self.params[key].get().strip()
            if val:
                arg_name = key
                if key == "from_path":
                    arg_name = "from"
                args.append(f"{arg_name}={val}")

        self.run_btn.config(state="disabled")
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")

        # Start execution thread
        threading.Thread(target=self.run_command_worker, args=(args,), daemon=True).start()

    def run_command_worker(self, args):
        try:
            self.root.after(0, self.append_log_safe, f"Executing: {' '.join(args)}\n")
    
            self.shell_process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # line-buffered
            )
    
            threading.Thread(
                target=self.read_stream,
                args=(self.shell_process.stdout, False),
                daemon=True
            ).start()
    
            threading.Thread(
                target=self.read_stream,
                args=(self.shell_process.stderr, True),
                daemon=True
            ).start()
    
            self.shell_process.wait()
    
        finally:
            self.root.after(0, lambda: self.run_btn.config(state="normal"))

    def read_stream(self, stream, is_error):
        for line in iter(stream.readline, ''):
            prefix = "ERROR: " if is_error else ""
            self.root.after(0, self.append_log_safe, prefix + line)
    
    
    # --- UI Update Helpers (Must be called via root.after or main thread) ---
    def update_log_window(self, message):
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")
    
    def append_log_safe(self, message):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")
    
    def log_safe(self, message):
        self.append_log_safe(message)

    def send_shell_input(self):
        if not self.shell_process:
            return
    
        text = self.shell_input.get()
        if not text:
            return
    
        try:
            self.shell_process.stdin.write(text + "\n")
            self.shell_process.stdin.flush()
            self.shell_input.delete(0, tk.END)
        except Exception as e:
            self.append_log_safe(f"\nFailed to send input: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = NtfstoolWrapperApp(root)
    root.mainloop()
