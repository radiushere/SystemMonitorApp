import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, scrolledtext
import psutil
import platform
import time
import threading
import datetime
import os
import sys
import logging
import socket

# --- Logging Setup ---
LOG_FILE = 'system_monitor_gui.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# --- App Class ---
class SystemMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced System Dashboard & Wellbeing")
        self.theme = "darkly" # Default theme
        self.style = tb.Style(theme=self.theme)
        self.root.geometry("1200x800") # Increased size for more content
        self.root.minsize(1000, 700) # Increased minimum size

        # Data storage for history and alerts
        self.cpu_history = [0] * 60 # Last 60 seconds
        self.mem_history = [0] * 60 # Last 60 seconds
        self.net_sent_history = [0] * 60
        self.net_recv_history = [0] * 60
        self.disk_read_history = [0] * 60
        self.disk_write_history = [0] * 60

        # Break timer variables (now integrated into Pomodoro)
        self.break_timer_active = False # Legacy, largely replaced by Pomodoro
        self.break_end_time = None # Legacy

        self.update_data_running = True # Flag to control data update loop

        # Alert thresholds (using Tkinter IntVars for easy binding)
        self.cpu_alert_threshold = tk.IntVar(value=90)
        self.mem_alert_threshold = tk.IntVar(value=90)
        self.disk_alert_threshold = tk.IntVar(value=90)
        self._last_alert_time = 0 # To prevent spamming alerts

        # Pomodoro timer variables
        self.pomodoro_state = "stopped" # "stopped", "work", "break", "long_break"
        self.pomodoro_work_duration = tk.IntVar(value=25)
        self.pomodoro_short_break_duration = tk.IntVar(value=5)
        self.pomodoro_long_break_duration = tk.IntVar(value=15)
        self.pomodoro_cycles = tk.IntVar(value=4) # Cycles before a long break
        self.current_pomodoro_cycle = 0
        self.pomodoro_end_time = None
        self.pomodoro_timer_id = None # To cancel after calls

        # Eye strain reminder variables
        self.eye_reminder_active = False
        self.eye_reminder_interval = tk.IntVar(value=20) # minutes
        self.eye_reminder_end_time = None
        self.eye_reminder_timer_id = None

        # --- Icon Mapping ---
        # Map custom icon names to actual Unicode emoji characters
        self.icon_map = {
            "cpu": "💻",
            "memory": "🧠",
            "hdd": "💾",
            "wifi": "📶",
            "battery-half": "🔋",
            "clock": "⏰",
            "thermometer": "🌡️",
            "list": "📋"
        }

        # List to hold individual CPU core meters
        self.cpu_core_meters = []

        # --- Notebook Layout (Main Tabs) ---
        # The bootstyle is applied to the notebook itself, not its individual tabs
        self.notebook = tb.Notebook(self.root, bootstyle="secondary")
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Create tabs. Removed bootstyle from add method as it's not supported.
        self._dashboard_tab()
        self._system_info_tab() # New tab for detailed system information
        self._processes_tab()
        self._network_tab() # New tab for network interface details and real-time usage
        self._logs_tab()
        self._wellbeing_tab()
        self._system_actions_tab() # New tab for shutdown/restart/logout
        self._settings_tab()

        # Start data update loop in the main thread using after()
        self.update_data()
        logger.info("Application started.")

        # Set protocol for closing window to ensure clean shutdown
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # --- Dashboard Tab ---
    def _dashboard_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard") # Corrected: No bootstyle here

        # Main grid for dashboard layout to organize cards and graphs
        main_grid = tb.Frame(tab)
        main_grid.pack(fill=BOTH, expand=True, padx=10, pady=10) # Increased padding
        # Configure grid columns and rows to expand proportionally
        main_grid.grid_columnconfigure(0, weight=1)
        main_grid.grid_columnconfigure(1, weight=1)
        main_grid.grid_rowconfigure(0, weight=1)
        main_grid.grid_rowconfigure(1, weight=1)

        # --- Top Section: System Overview Cards ---
        cards_frame = tb.Frame(main_grid, bootstyle="light") # Frame to hold all the cards
        cards_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        # Configure card frame columns to expand evenly
        cards_frame.grid_columnconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(1, weight=1)
        cards_frame.grid_columnconfigure(2, weight=1)
        cards_frame.grid_columnconfigure(3, weight=1)

        self.cards = {} # Dictionary to store references to value labels for easy update
        card_info = [
            ("CPU Usage", "cpu", "info", 0, 0),
            ("Memory Usage", "memory", "success", 0, 1),
            ("Disk Usage", "hdd", "warning", 0, 2),
            ("Network I/O", "wifi", "primary", 0, 3),
            ("Battery", "battery-half", "danger", 1, 0),
            ("Uptime", "clock", "secondary", 1, 1),
            ("CPU Temp", "thermometer", "dark", 1, 2), # New: CPU Temperature (requires `psutil.sensors_temperatures()`)
            ("Processes", "list", "light", 1, 3) # New: Total Process Count
        ]

        for i, (label, icon, style, r, c) in enumerate(card_info):
            # Create a card frame for each metric
            card = tb.Frame(cards_frame, bootstyle=style, padding=15, relief="flat", borderwidth=1, cursor="hand2")
            card.grid(row=r, column=c, padx=8, pady=8, sticky="nsew")
            cards_frame.grid_rowconfigure(r, weight=1) # Make rows in card frame expand

            # Icon label using the custom icon_map for emoji characters
            icon_label = tb.Label(card, text=self.icon_map.get(icon, '❓'), font=("Segoe UI Emoji", 28), bootstyle=style)
            icon_label.pack(anchor=W, pady=(0, 5))
            # Value label to display the current metric value
            value_label = tb.Label(card, text="...", font=("Segoe UI", 18, "bold"), bootstyle=style)
            value_label.pack(anchor=W)
            # Description label for the metric
            desc_label = tb.Label(card, text=label, font=("Segoe UI", 10), bootstyle=style)
            desc_label.pack(anchor=W)
            self.cards[label] = value_label # Store reference to the value label

        # --- Bottom Section: Performance Graphs (Meters and Floodgauges) ---
        graphs_frame = tb.Frame(main_grid, bootstyle="secondary") # Frame to hold performance meters
        graphs_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=10) # Increased padding
        graphs_frame.grid_columnconfigure(0, weight=1)
        graphs_frame.grid_columnconfigure(1, weight=1)
        graphs_frame.grid_columnconfigure(2, weight=1) # For Disk I/O gauges
        graphs_frame.grid_rowconfigure(0, weight=1)

        # CPU Meter (full circle meter)
        self.cpu_meter = tb.Meter(
            graphs_frame,
            metersize=180,
            padding=10,
            amountused=0,
            metertype="full",
            bootstyle="info",
            subtext="CPU Usage",
            textfont="-size 12 -weight bold",
            interactive=False # Not interactive
        )
        self.cpu_meter.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Memory Meter (full circle meter)
        self.mem_meter = tb.Meter(
            graphs_frame,
            metersize=180,
            padding=10,
            amountused=0,
            metertype="full",
            bootstyle="success",
            subtext="RAM Usage",
            textfont="-size 12 -weight bold",
            interactive=False
        )
        self.mem_meter.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Disk I/O Gauges (using Floodgauge for a different visual representation)
        disk_io_frame = tb.Frame(graphs_frame, bootstyle="dark")
        disk_io_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
        disk_io_frame.grid_rowconfigure(0, weight=1)
        disk_io_frame.grid_rowconfigure(1, weight=1)
        disk_io_frame.grid_columnconfigure(0, weight=1)

        tb.Label(disk_io_frame, text="Disk I/O (MB/s)", font=("Segoe UI", 12, "bold"), bootstyle="dark").pack(pady=(5,0))
        self.disk_read_gauge = tb.Floodgauge(
            disk_io_frame,
            font=("Segoe UI", 10),
            bootstyle="warning",
            mask="Read: {} MB/s", # Text format for the gauge
            maximum=100, # Max value for gauge, adjust based on expected max disk speed
            value=0
        )
        self.disk_read_gauge.pack(fill=X, padx=10, pady=5)

        self.disk_write_gauge = tb.Floodgauge(
            disk_io_frame,
            font=("Segoe UI", 10),
            bootstyle="danger",
            mask="Write: {} MB/s",
            maximum=100, # Max value for gauge
            value=0
        )
        self.disk_write_gauge.pack(fill=X, padx=10, pady=5)

    # --- System Info Tab ---
    def _system_info_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="System Info")

        # Main frame for System Info tab
        info_main_frame = tb.Frame(tab, padding=15)
        info_main_frame.pack(fill=BOTH, expand=True)

        # Configure grid for two main columns
        info_main_frame.grid_columnconfigure(0, weight=1)
        info_main_frame.grid_columnconfigure(1, weight=1)
        info_main_frame.grid_rowconfigure(0, weight=1) # Treeview
        info_main_frame.grid_rowconfigure(1, weight=1) # Core Usage

        # Left side: System Information Treeview
        info_tree_frame = tb.LabelFrame(info_main_frame, text="System Overview", bootstyle="primary", padding=10)
        info_tree_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        info_tree_frame.grid_rowconfigure(0, weight=1)
        info_tree_frame.grid_columnconfigure(0, weight=1)

        self.sys_info_tree = tb.Treeview(info_tree_frame, columns=("Property", "Value"), show="headings", bootstyle="primary")
        self.sys_info_tree.heading("Property", text="Property")
        self.sys_info_tree.heading("Value", text="Value")
        self.sys_info_tree.column("Property", width=200, anchor=W)
        self.sys_info_tree.column("Value", width=400, anchor=W)
        self.sys_info_tree.pack(fill=BOTH, expand=True) # Removed padx/pady as it's handled by parent frame

        self._populate_system_info() # Populate data on tab creation

        # Right side: Individual CPU Core Usage Meters
        cpu_core_frame = tb.LabelFrame(info_main_frame, text="Individual CPU Core Usage", bootstyle="info", padding=10)
        cpu_core_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        cpu_core_frame.grid_rowconfigure(0, weight=1) # Allow content to expand

        # Create a canvas inside the frame to allow scrolling if many cores
        self.cpu_core_canvas = tk.Canvas(cpu_core_frame, highlightthickness=0, bg=self.style.colors.bg)
        self.cpu_core_canvas.pack(side=LEFT, fill=BOTH, expand=True)

        self.cpu_core_scrollbar = tb.Scrollbar(cpu_core_frame, orient="vertical", command=self.cpu_core_canvas.yview, bootstyle="info-round")
        self.cpu_core_scrollbar.pack(side=RIGHT, fill="y")

        self.cpu_core_canvas.configure(yscrollcommand=self.cpu_core_scrollbar.set)
        self.cpu_core_canvas.bind('<Configure>', lambda e: self.cpu_core_canvas.configure(scrollregion = self.cpu_core_canvas.bbox("all")))

        self.cpu_core_inner_frame = tb.Frame(self.cpu_core_canvas)
        self.cpu_core_canvas.create_window((0, 0), window=self.cpu_core_inner_frame, anchor="nw", width=self.cpu_core_canvas.winfo_width())

        # Bind canvas resize to update inner frame width
        self.cpu_core_canvas.bind('<Configure>', self._on_cpu_core_canvas_resize)

        self._create_cpu_core_meters() # Create meters dynamically based on CPU count

    def _on_cpu_core_canvas_resize(self, event):
        self.cpu_core_canvas.itemconfig(self.cpu_core_canvas.find_withtag("all")[0], width=event.width)
        self.cpu_core_canvas.configure(scrollregion=self.cpu_core_canvas.bbox("all"))

    def _create_cpu_core_meters(self):
        # Clear existing meters if any
        for meter in self.cpu_core_meters:
            meter.destroy()
        self.cpu_core_meters.clear()

        logical_cores = psutil.cpu_count(logical=True)
        if logical_cores is None:
            tb.Label(self.cpu_core_inner_frame, text="Could not detect CPU cores.", bootstyle="danger").pack(pady=10)
            return

        for i in range(logical_cores):
            # Using a horizontal Floodgauge for a more compact bar-like display
            meter = tb.Floodgauge(
                self.cpu_core_inner_frame,
                font=("Segoe UI", 9, "bold"),
                bootstyle="info",
                mask=f"Core {i}: {{}}%", # Text format for the gauge
                maximum=100,
                value=0,
                orient=HORIZONTAL,
                length=250 # Fixed length, will be adjusted by grid/pack
            )
            meter.pack(fill=X, padx=5, pady=2) # Pack with minimal padding
            self.cpu_core_meters.append(meter)

    def _populate_system_info(self):
        # Clear existing items before repopulating
        for item in self.sys_info_tree.get_children():
            self.sys_info_tree.delete(item)

        # OS Information
        self.sys_info_tree.insert("", "end", text="OS", values=("Operating System", platform.system()), open=True, tags=('header',))
        self.sys_info_tree.insert("", "end", values=("OS Release", platform.release()))
        self.sys_info_tree.insert("", "end", values=("OS Version", platform.version()))
        self.sys_info_tree.insert("", "end", values=("Architecture", platform.machine()))
        self.sys_info_tree.insert("", "end", values=("Node Name", platform.node()))

        # CPU Information
        self.sys_info_tree.insert("", "end", text="CPU", values=("Processor", platform.processor()), open=True, tags=('header',))
        self.sys_info_tree.insert("", "end", values=("Physical Cores", psutil.cpu_count(logical=False)))
        self.sys_info_tree.insert("", "end", values=("Logical Cores", psutil.cpu_count(logical=True)))
        try:
            cpu_freq = psutil.cpu_freq()
            self.sys_info_tree.insert("", "end", values=("Current Frequency", f"{cpu_freq.current:.2f} MHz"))
            self.sys_info_tree.insert("", "end", values=("Max Frequency", f"{cpu_freq.max:.2f} MHz"))
        except Exception:
            self.sys_info_tree.insert("", "end", values=("Frequency", "N/A"))

        # Memory Information
        mem = psutil.virtual_memory()
        self.sys_info_tree.insert("", "end", text="Memory", values=("Total RAM", f"{mem.total / (1024**3):.2f} GB"), open=True, tags=('header',))
        self.sys_info_tree.insert("", "end", values=("Available RAM", f"{mem.available / (1024**3):.2f} GB"))
        self.sys_info_tree.insert("", "end", values=("Used RAM", f"{mem.used / (1024**3):.2f} GB ({mem.percent:.1f}%)"))
        swap = psutil.swap_memory()
        self.sys_info_tree.insert("", "end", values=("Swap Total", f"{swap.total / (1024**3):.2f} GB"))
        self.sys_info_tree.insert("", "end", values=("Swap Used", f"{swap.used / (1024**3):.2f} GB ({swap.percent:.1f}%)"))

        # Disk Partitions
        self.sys_info_tree.insert("", "end", text="Disks", values=("", ""), open=True, tags=('header',))
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                self.sys_info_tree.insert("", "end", values=(f"  {part.device} ({part.mountpoint})",
                                                            f"Total: {usage.total / (1024**3):.2f} GB, Used: {usage.used / (1024**3):.2f} GB ({usage.percent:.1f}%)"))
            except Exception as e:
                logger.warning(f"Could not get disk usage for {part.mountpoint}: {e}")
                self.sys_info_tree.insert("", "end", values=(f"  {part.device} ({part.mountpoint})", "N/A"))

        # Apply a tag style for headers
        self.sys_info_tree.tag_configure('header', font=("Segoe UI", 11, "bold"), foreground="blue")


    # --- Processes Tab ---
    def _processes_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Processes")

        # Top control frame for search and action buttons
        top_frame = tb.Frame(tab, padding=10)
        top_frame.pack(fill=X)

        tb.Label(top_frame, text="Search:", font=("Segoe UI", 11)).pack(side=LEFT, padx=(0, 5))
        self.proc_search_var = tk.StringVar()
        self.proc_search_var.trace_add('write', self._update_process_list) # Update on typing
        tb.Entry(top_frame, textvariable=self.proc_search_var, width=30, bootstyle="primary").pack(side=LEFT, padx=5)

        self.proc_refresh_btn = tb.Button(top_frame, text="Refresh", bootstyle="info-outline", command=self._update_process_list)
        self.proc_refresh_btn.pack(side=LEFT, padx=5)

        self.kill_proc_btn = tb.Button(top_frame, text="Kill Process", bootstyle="danger", command=self._kill_selected_process)
        self.kill_proc_btn.pack(side=LEFT, padx=5)

        # Process list Treeview with more columns
        self.proc_list = tb.Treeview(tab, columns=("PID", "Name", "CPU %", "MEM %", "User", "Status", "Threads", "Priority"),
                                     show="headings", height=25, bootstyle="primary")

        # Define column headings and widths
        for col in ("PID", "Name", "CPU %", "MEM %", "User", "Status", "Threads", "Priority"):
            self.proc_list.heading(col, text=col, anchor=W)
            # Adjust column widths for better readability
            self.proc_list.column(col, width=80 if col in ("PID", "CPU %", "MEM %", "Threads") else (120 if col in ("User", "Status", "Priority") else 250), anchor=W)

        self.proc_list.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Initial population of the process list
        self._update_process_list()

    def _update_process_list(self, *args):
        search_term = self.proc_search_var.get().lower()
        for row in self.proc_list.get_children():
            self.proc_list.delete(row) # Clear existing entries

        procs_data = []
        # Iterate over all running processes and gather relevant info
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'status', 'num_threads', 'nice']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                cpu_percent = f"{info['cpu_percent']:.1f}"
                mem_percent = f"{info['memory_percent']:.1f}"
                username = info['username'] if info['username'] else "N/A"
                status = info['status']
                num_threads = info['num_threads']
                priority = info['nice'] # 'nice' is priority on Unix, 'priority' on Windows

                # Apply search filter
                if search_term and not (search_term in name.lower() or search_term in str(pid)):
                    continue

                procs_data.append((pid, name, cpu_percent, mem_percent, username[:15], status, num_threads, priority))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle processes that might disappear or deny access during iteration
                continue
            except Exception as e:
                logger.error(f"Error getting process info for PID {proc.pid}: {e}")

        # Sort by CPU usage (descending) and limit to top 100 for performance
        procs_data = sorted(procs_data, key=lambda x: float(x[2]), reverse=True)[:100]

        # Insert sorted data into the Treeview
        for p in procs_data:
            self.proc_list.insert("", "end", values=p)

    def _kill_selected_process(self):
        selected_item = self.proc_list.focus() # Get the currently selected item
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a process to kill.")
            return

        values = self.proc_list.item(selected_item, 'values')
        pid = int(values[0])
        name = values[1]

        # Confirmation dialog before killing a process
        if messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill process:\nPID: {pid}\nName: {name}? This action cannot be undone."):
            try:
                p = psutil.Process(pid)
                p.terminate() # Attempt to terminate gracefully
                p.wait(timeout=3) # Wait for process to terminate
                if p.is_running():
                    p.kill() # Force kill if still running
                logger.info(f"Terminated process: PID={pid}, Name={name}")
                self._update_process_list() # Refresh list after killing
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", f"Process with PID {pid} not found. It might have already exited.")
                logger.error(f"Attempted to kill non-existent process: PID={pid}")
            except psutil.AccessDenied:
                messagebox.showerror("Permission Denied", f"Access denied to kill process with PID {pid}. You may need to run the application as administrator.")
                logger.error(f"Access denied to kill process: PID={pid}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not kill process: {e}")
                logger.error(f"Error killing process PID={pid}: {e}")

    # --- Network Tab ---
    def _network_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Network")

        # Frame for network interface details
        interface_frame = tb.LabelFrame(tab, text="Network Interfaces", bootstyle="primary", padding=15)
        interface_frame.pack(fill=X, padx=10, pady=10)

        self.net_if_tree = tb.Treeview(interface_frame, columns=("Interface", "IP", "MAC", "Status"), show="headings", bootstyle="primary")
        self.net_if_tree.heading("Interface", text="Interface")
        self.net_if_tree.heading("IP", text="IP Address")
        self.net_if_tree.heading("MAC", text="MAC Address")
        self.net_if_tree.heading("Status", text="Status")
        self.net_if_tree.column("Interface", width=150)
        self.net_if_tree.column("IP", width=150)
        self.net_if_tree.column("MAC", width=150)
        self.net_if_tree.column("Status", width=100)
        self.net_if_tree.pack(fill=BOTH, expand=True)

        self._populate_network_interfaces() # Populate initial network interface data

        # Frame for real-time network usage
        net_usage_frame = tb.LabelFrame(tab, text="Real-time Usage", bootstyle="info", padding=15)
        net_usage_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        self.net_total_sent_label = tb.Label(net_usage_frame, text="Total Sent: 0 MB", font=("Segoe UI", 12, "bold"))
        self.net_total_sent_label.pack(anchor=W, pady=5)
        self.net_total_recv_label = tb.Label(net_usage_frame, text="Total Received: 0 MB", font=("Segoe UI", 12, "bold"))
        self.net_total_recv_label.pack(anchor=W, pady=5)

        # Frame for per-interface usage (dynamically updated)
        self.per_if_frame = tb.LabelFrame(net_usage_frame, text="Per Interface (Current Speed)", bootstyle="secondary", padding=10)
        self.per_if_frame.pack(fill=BOTH, expand=True, pady=(10,0))
        # A placeholder label that will be replaced by dynamic interface labels
        tb.Label(self.per_if_frame, text="Updating...", bootstyle="secondary").pack()


    def _populate_network_interfaces(self):
        # Clear existing items in the Treeview
        for item in self.net_if_tree.get_children():
            self.net_if_tree.delete(item)

        interfaces = psutil.net_if_addrs() # Get network interface addresses
        stats = psutil.net_if_stats() # Get network interface statistics (e.g., isup)

        for name, addrs in interfaces.items():
            ip_addr = "N/A"
            mac_addr = "N/A"
            status = "Unknown"

            for addr in addrs:
                # Use socket.AF_INET and socket.AF_LINK for address family comparison
                if addr.family == socket.AF_INET: # IPv4 address
                    ip_addr = addr.address
                elif addr.family == socket.AF_LINK: # MAC address
                    mac_addr = addr.address

            if name in stats:
                status = "Up" if stats[name].isup else "Down" # Check if interface is up

            self.net_if_tree.insert("", "end", values=(name, ip_addr, mac_addr, status))

    # --- Logs Tab ---
    def _logs_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Logs")

        log_frame = tb.Frame(tab, padding=10)
        log_frame.pack(fill=BOTH, expand=True)

        # ScrolledText widget for displaying logs
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', height=20,
                                                  font=("Consolas", 10), bg="#1e1e1e", fg="#cccccc",
                                                  insertbackground="#cccccc") # Dark theme colors for log text
        self.log_text.pack(fill=BOTH, expand=True)

        # Buttons for log management
        btn_frame = tb.Frame(log_frame, padding=(0, 10))
        btn_frame.pack(fill=X)
        tb.Button(btn_frame, text="Open Log File", bootstyle="info-outline", command=self.open_log_file).pack(side=LEFT, padx=5)
        tb.Button(btn_frame, text="Clear Log Display", bootstyle="warning-outline", command=self.clear_log_display).pack(side=LEFT, padx=5)

        logger.addHandler(GuiHandler(self.log_text)) # Attach custom GUI handler to the logger

    def clear_log_display(self):
        self.log_text.configure(state='normal') # Enable editing temporarily
        self.log_text.delete(1.0, tk.END) # Delete all text
        self.log_text.configure(state='disabled') # Disable editing
        logger.info("Log display cleared by user.")

    # --- Wellbeing Tab ---
    def _wellbeing_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Wellbeing")

        wellbeing_frame = tb.Frame(tab, padding=20)
        wellbeing_frame.pack(fill=BOTH, expand=True)

        # Pomodoro Timer Section
        pomodoro_card = tb.LabelFrame(wellbeing_frame, text="Pomodoro Timer", bootstyle="info", padding=15)
        pomodoro_card.pack(fill=X, padx=10, pady=10)

        # Pomodoro settings inputs
        tb.Label(pomodoro_card, text="Work Duration (min):", font=("Segoe UI", 11)).grid(row=0, column=0, sticky=W, pady=5, padx=5)
        tb.Entry(pomodoro_card, textvariable=self.pomodoro_work_duration, width=5).grid(row=0, column=1, sticky=W, pady=5, padx=5)

        tb.Label(pomodoro_card, text="Short Break (min):", font=("Segoe UI", 11)).grid(row=1, column=0, sticky=W, pady=5, padx=5)
        tb.Entry(pomodoro_card, textvariable=self.pomodoro_short_break_duration, width=5).grid(row=1, column=1, sticky=W, pady=5, padx=5)

        tb.Label(pomodoro_card, text="Long Break (min):", font=("Segoe UI", 11)).grid(row=2, column=0, sticky=W, pady=5, padx=5)
        tb.Entry(pomodoro_card, textvariable=self.pomodoro_long_break_duration, width=5).grid(row=2, column=1, sticky=W, pady=5, padx=5)

        tb.Label(pomodoro_card, text="Cycles before Long Break:", font=("Segoe UI", 11)).grid(row=3, column=0, sticky=W, pady=5, padx=5)
        tb.Entry(pomodoro_card, textvariable=self.pomodoro_cycles, width=5).grid(row=3, column=1, sticky=W, pady=5, padx=5)

        # Pomodoro control buttons
        pomodoro_btn_frame = tb.Frame(pomodoro_card)
        pomodoro_btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        self.pomodoro_start_btn = tb.Button(pomodoro_btn_frame, text="Start Pomodoro", bootstyle="success", command=self.start_pomodoro)
        self.pomodoro_start_btn.pack(side=LEFT, padx=5)
        self.pomodoro_stop_btn = tb.Button(pomodoro_btn_frame, text="Stop", bootstyle="danger", command=self.stop_pomodoro, state=DISABLED)
        self.pomodoro_stop_btn.pack(side=LEFT, padx=5)
        self.pomodoro_skip_btn = tb.Button(pomodoro_btn_frame, text="Skip", bootstyle="warning", command=self.skip_pomodoro, state=DISABLED)
        self.pomodoro_skip_btn.pack(side=LEFT, padx=5)

        # Pomodoro timer status label
        self.pomodoro_timer_label = tb.Label(pomodoro_card, text="Status: Stopped", font=("Segoe UI", 14, "bold"), bootstyle="info")
        self.pomodoro_timer_label.grid(row=5, column=0, columnspan=2, pady=10)

        # Eye Strain Reminder Section
        eye_reminder_card = tb.LabelFrame(wellbeing_frame, text="Eye Strain Reminder (20-20-20 Rule)", bootstyle="warning", padding=15)
        eye_reminder_card.pack(fill=X, padx=10, pady=10)

        tb.Label(eye_reminder_card, text="Remind every (minutes):", font=("Segoe UI", 11)).pack(side=LEFT, padx=(0, 5))
        tb.Entry(eye_reminder_card, textvariable=self.eye_reminder_interval, width=5).pack(side=LEFT, padx=5)
        self.eye_reminder_start_btn = tb.Button(eye_reminder_card, text="Start Reminder", bootstyle="success", command=self.start_eye_reminder)
        self.eye_reminder_start_btn.pack(side=LEFT, padx=5)
        self.eye_reminder_stop_btn = tb.Button(eye_reminder_card, text="Stop Reminder", bootstyle="danger", command=self.stop_eye_reminder, state=DISABLED)
        self.eye_reminder_stop_btn.pack(side=LEFT, padx=5)
        self.eye_reminder_label = tb.Label(eye_reminder_card, text="Status: Stopped", font=("Segoe UI", 12, "bold"))
        self.eye_reminder_label.pack(anchor=W, pady=10)

    # --- Pomodoro Timer Logic ---
    def start_pomodoro(self):
        if self.pomodoro_state != "stopped":
            self.stop_pomodoro() # Reset if already running or restarting

        try:
            work_duration = self.pomodoro_work_duration.get()
            short_break = self.pomodoro_short_break_duration.get()
            long_break = self.pomodoro_long_break_duration.get()
            cycles = self.pomodoro_cycles.get()

            # Input validation
            if not all(x > 0 for x in [work_duration, short_break, long_break, cycles]):
                messagebox.showwarning("Invalid Input", "All Pomodoro durations and cycles must be positive integers.")
                return

            self.current_pomodoro_cycle = 0 # Reset cycle count
            self.pomodoro_state = "work"
            self.pomodoro_start_time = time.time()
            self.pomodoro_end_time = self.pomodoro_start_time + work_duration * 60
            self.pomodoro_start_btn.config(text="Restart", bootstyle="warning")
            self.pomodoro_stop_btn.config(state=NORMAL)
            self.pomodoro_skip_btn.config(state=NORMAL)
            logger.info(f"Pomodoro started: Work for {work_duration} min.")
            self._update_pomodoro_timer() # Start the timer update loop

        except Exception as e:
            messagebox.showerror("Error", f"Could not start Pomodoro: {e}")
            logger.error(f"Error starting Pomodoro: {e}")

    def _update_pomodoro_timer(self):
        if self.pomodoro_state == "stopped":
            self.pomodoro_timer_label.config(text="Status: Stopped")
            return

        remaining = self.pomodoro_end_time - time.time()
        mins, secs = divmod(int(remaining), 60)

        if remaining <= 0:
            self._handle_pomodoro_completion() # Handle phase transition
        else:
            status_text = ""
            if self.pomodoro_state == "work":
                status_text = f"Work Cycle {self.current_pomodoro_cycle + 1}/{self.pomodoro_cycles.get()}: {mins:02d}:{secs:02d}"
            elif self.pomodoro_state == "break":
                status_text = f"Short Break: {mins:02d}:{secs:02d}"
            elif self.pomodoro_state == "long_break":
                status_text = f"Long Break: {mins:02d}:{secs:02d}"

            self.pomodoro_timer_label.config(text=status_text)
            self.pomodoro_timer_id = self.root.after(1000, self._update_pomodoro_timer) # Schedule next update

    def _handle_pomodoro_completion(self):
        if self.pomodoro_state == "work":
            self.current_pomodoro_cycle += 1
            if self.current_pomodoro_cycle % self.pomodoro_cycles.get() == 0:
                self.pomodoro_state = "long_break"
                duration = self.pomodoro_long_break_duration.get()
                messagebox.showinfo("Pomodoro", "Time for a LONG break!")
                logger.info(f"Pomodoro: Starting long break for {duration} min.")
            else:
                self.pomodoro_state = "break"
                duration = self.pomodoro_short_break_duration.get()
                messagebox.showinfo("Pomodoro", "Time for a short break!")
                logger.info(f"Pomodoro: Starting short break for {duration} min.")

            self.pomodoro_end_time = time.time() + duration * 60
            self._update_pomodoro_timer() # Continue timer
            
        elif self.pomodoro_state in ["break", "long_break"]:
            self.pomodoro_state = "work"
            duration = self.pomodoro_work_duration.get()
            messagebox.showinfo("Pomodoro", "Break over! Time to work.")
            logger.info(f"Pomodoro: Starting work for {duration} min.")
            self.pomodoro_end_time = time.time() + duration * 60
            self._update_pomodoro_timer() # Continue timer

    def stop_pomodoro(self):
        if self.pomodoro_timer_id:
            self.root.after_cancel(self.pomodoro_timer_id) # Cancel scheduled updates
            self.pomodoro_timer_id = None
        self.pomodoro_state = "stopped"
        self.pomodoro_end_time = None
        self.current_pomodoro_cycle = 0
        self.pomodoro_timer_label.config(text="Status: Stopped")
        self.pomodoro_start_btn.config(text="Start Pomodoro", bootstyle="success")
        self.pomodoro_stop_btn.config(state=DISABLED)
        self.pomodoro_skip_btn.config(state=DISABLED)
        logger.info("Pomodoro timer stopped.")

    def skip_pomodoro(self):
        if self.pomodoro_state != "stopped":
            self._handle_pomodoro_completion() # Force transition to next phase
            logger.info("Pomodoro cycle skipped.")

    # --- Eye Strain Reminder Logic ---
    def start_eye_reminder(self):
        if self.eye_reminder_active:
            self.stop_eye_reminder() # Reset if already running

        try:
            interval = self.eye_reminder_interval.get()
            if interval <= 0:
                messagebox.showwarning("Invalid Input", "Reminder interval must be positive.")
                return

            self.eye_reminder_active = True
            self.eye_reminder_start_time = time.time()
            self.eye_reminder_end_time = self.eye_reminder_start_time + interval * 60
            self.eye_reminder_start_btn.config(state=DISABLED)
            self.eye_reminder_stop_btn.config(state=NORMAL)
            logger.info(f"Eye strain reminder started for every {interval} minutes.")
            self._update_eye_reminder_timer()

        except Exception as e:
            messagebox.showerror("Error", f"Could not start eye reminder: {e}")
            logger.error(f"Error starting eye reminder: {e}")

    def _update_eye_reminder_timer(self):
        if not self.eye_reminder_active:
            self.eye_reminder_label.config(text="Status: Stopped")
            return

        remaining = self.eye_reminder_end_time - time.time()
        mins, secs = divmod(int(remaining), 60)

        if remaining <= 0:
            messagebox.showinfo("Eye Strain Reminder", "Look away from the screen for 20 seconds! Focus on something 20 feet away.")
            logger.info("Eye strain reminder triggered.")
            # Reset timer for next interval
            interval = self.eye_reminder_interval.get()
            self.eye_reminder_end_time = time.time() + interval * 60
            self.eye_reminder_label.config(text=f"Next reminder in: {interval:02d}:00")
            self.eye_reminder_timer_id = self.root.after(1000, self._update_eye_reminder_timer) # Continue updating
        else:
            self.eye_reminder_label.config(text=f"Next reminder in: {mins:02d}:{secs:02d}")
            self.eye_reminder_timer_id = self.root.after(1000, self._update_eye_reminder_timer)

    def stop_eye_reminder(self):
        if self.eye_reminder_timer_id:
            self.root.after_cancel(self.eye_reminder_timer_id)
            self.eye_reminder_timer_id = None
        self.eye_reminder_active = False
        self.eye_reminder_end_time = None
        self.eye_reminder_label.config(text="Status: Stopped")
        self.eye_reminder_start_btn.config(state=NORMAL)
        self.eye_reminder_stop_btn.config(state=DISABLED)
        logger.info("Eye strain reminder stopped.")

    # --- System Actions Tab ---
    def _system_actions_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="System Actions")

        actions_frame = tb.LabelFrame(tab, text="System Power Options", bootstyle="danger", padding=20)
        actions_frame.pack(fill=X, padx=20, pady=20)

        tb.Label(actions_frame, text="Use these options with caution! They will immediately affect your system.",
                 font=("Segoe UI", 12, "bold"), bootstyle="danger").pack(pady=10)

        # Determine button style based on current theme for better contrast
        btn_style = "outline-danger" if self.theme == "darkly" else "danger"

        tb.Button(actions_frame, text="Shutdown System", bootstyle=btn_style, command=self._shutdown_system).pack(fill=X, pady=5)
        tb.Button(actions_frame, text="Restart System", bootstyle=btn_style, command=self._restart_system).pack(fill=X, pady=5)
        tb.Button(actions_frame, text="Logout User", bootstyle=btn_style, command=self._logout_user).pack(fill=X, pady=5)

    def _shutdown_system(self):
        if messagebox.askyesno("Confirm Shutdown", "Are you sure you want to SHUTDOWN the system immediately? All unsaved work will be lost."):
            logger.warning("System shutdown initiated by user.")
            try:
                if platform.system() == "Windows":
                    os.system("shutdown /s /t 1") # /s for shutdown, /t 1 for 1 second delay
                elif platform.system() == "Linux" or platform.system() == "Darwin": # macOS
                    os.system("sudo shutdown -h now") # -h for halt (shutdown), now for immediate
                else:
                    messagebox.showerror("Error", "Unsupported operating system for direct shutdown.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to shutdown: {e}\n(Requires administrator/root privileges)")
                logger.error(f"Failed to shutdown system: {e}")

    def _restart_system(self):
        if messagebox.askyesno("Confirm Restart", "Are you sure you want to RESTART the system immediately? All unsaved work will be lost."):
            logger.warning("System restart initiated by user.")
            try:
                if platform.system() == "Windows":
                    os.system("shutdown /r /t 1") # /r for restart
                elif platform.system() == "Linux" or platform.system() == "Darwin": # macOS
                    os.system("sudo shutdown -r now") # -r for reboot (restart)
                else:
                    messagebox.showerror("Error", "Unsupported operating system for direct restart.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restart: {e}\n(Requires administrator/root privileges)")
                logger.error(f"Failed to restart system: {e}")

    def _logout_user(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to LOGOUT the current user immediately?"):
            logger.warning("User logout initiated by user.")
            try:
                if platform.system() == "Windows":
                    os.system("shutdown /l") # /l for logoff
                elif platform.system() == "Linux":
                    # This is more complex and depends on the desktop environment.
                    # 'pkill -KILL -u $USER' is a forceful way to kill all user processes,
                    # which often leads to a logout. It might not be graceful.
                    os.system("pkill -KILL -u $USER")
                    messagebox.showinfo("Logout", "Attempted to log out. This might not work on all Linux setups or might not be graceful.")
                elif platform.system() == "Darwin": # macOS
                    messagebox.showinfo("Logout", "On macOS, please use the Apple menu to logout for a graceful exit.")
                else:
                    messagebox.showerror("Error", "Unsupported operating system for direct logout.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to logout: {e}")
                logger.error(f"Failed to logout user: {e}")

    # --- Settings Tab ---
    def _settings_tab(self):
        tab = tb.Frame(self.notebook)
        self.notebook.add(tab, text="Settings")

        settings_frame = tb.Frame(tab, padding=20)
        settings_frame.pack(fill=BOTH, expand=True)

        # Theme selection
        tb.Label(settings_frame, text="Application Theme:", font=("Segoe UI", 12, "bold")).pack(anchor=W, padx=10, pady=(10, 5))
        theme_combo = tb.Combobox(settings_frame, values=self.style.theme_names(), width=25, bootstyle="primary")
        theme_combo.set(self.theme)
        theme_combo.pack(anchor=W, padx=10, pady=5)
        theme_combo.bind("<<ComboboxSelected>>", lambda e: self.set_theme(theme_combo.get()))

        # Alert thresholds section
        alert_frame = tb.LabelFrame(settings_frame, text="Alert Thresholds (%)", bootstyle="warning", padding=15)
        alert_frame.pack(fill=X, padx=10, pady=15)

        # CPU Alert
        tb.Label(alert_frame, text="CPU Usage:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky=W, padx=5, pady=5)
        tb.Entry(alert_frame, textvariable=self.cpu_alert_threshold, width=6, bootstyle="warning").grid(row=0, column=1, sticky=W, padx=5, pady=5)

        # Memory Alert
        tb.Label(alert_frame, text="Memory Usage:", font=("Segoe UI", 11)).grid(row=1, column=0, sticky=W, padx=5, pady=5)
        tb.Entry(alert_frame, textvariable=self.mem_alert_threshold, width=6, bootstyle="warning").grid(row=1, column=1, sticky=W, padx=5, pady=5)

        # Disk Alert
        tb.Label(alert_frame, text="Disk Usage:", font=("Segoe UI", 11)).grid(row=2, column=0, sticky=W, padx=5, pady=5)
        tb.Entry(alert_frame, textvariable=self.disk_alert_threshold, width=6, bootstyle="warning").grid(row=2, column=1, sticky=W, padx=5, pady=5)

        tb.Button(settings_frame, text="Apply Settings", bootstyle="success", command=self.apply_settings).pack(anchor=W, padx=10, pady=20)

        # About section
        about_frame = tb.LabelFrame(settings_frame, text="About", bootstyle="secondary", padding=15)
        about_frame.pack(side=BOTTOM, fill=X, padx=10, pady=10)
        tb.Label(about_frame, text="Advanced System Dashboard & Wellbeing v3.1\nDeveloped by radiushere",
                 font=("Segoe UI", 10, "italic"), bootstyle="secondary").pack(pady=5)

    # --- Data Update Loop ---
    def update_data(self):
        # Stop updating if the flag is set to False (e.g., on app closing)
        if not self.update_data_running:
            return

        try:
            # --- System Metrics Collection ---
            cpu_percent_overall = psutil.cpu_percent(interval=None) # Overall CPU usage
            cpu_per_core_percents = psutil.cpu_percent(interval=None, percpu=True) # Per-core CPU usage
            mem_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            net_io = psutil.net_io_counters()
            battery_info = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
            uptime_seconds = time.time() - psutil.boot_time()
            
            # CPU Temperature: Try to find a common sensor label or the first available
            temp_value = "N/A"
            found_temp = False
            if hasattr(psutil, "sensors_temperatures"):
                cpu_temps = psutil.sensors_temperatures()
                # Prioritize common CPU-related sensor labels
                for sensor_name, entries in cpu_temps.items():
                    for entry in entries:
                        if ('cpu' in sensor_name.lower() or 'core' in sensor_name.lower() or 
                            'package' in entry.label.lower() or 'temp' in entry.label.lower()):
                            temp_value = f"{entry.current:.1f}°C"
                            found_temp = True
                            break # Found a relevant CPU temp, break inner loop
                    if found_temp:
                        break # Found a relevant CPU temp, break outer loop

                # If no specific CPU temp found, just take the first available temperature
                if not found_temp and cpu_temps:
                    # Iterate through all entries to find any temperature reading
                    for sensor_name, entries in cpu_temps.items():
                        if entries:
                            temp_value = f"{entries[0].current:.1f}°C (Generic)"
                            found_temp = True
                            break
            self.cards["CPU Temp"].config(text=temp_value)

            process_count = len(psutil.pids())

            # --- Update Dashboard Cards ---
            self.cards["CPU Usage"].config(text=f"{cpu_percent_overall:.1f}%")
            self.cards["Memory Usage"].config(text=f"{mem_info.percent:.1f}%")
            self.cards["Disk Usage"].config(text=f"{disk_info.percent:.1f}%")
            self.cards["Network I/O"].config(text=f"{net_io.bytes_sent/1024/1024:.1f} MB ↑ / {net_io.bytes_recv/1024/1024:.1f} MB ↓")
            if battery_info:
                self.cards["Battery"].config(text=f"{battery_info.percent:.1f}% {'⚡' if battery_info.power_plugged else ''}")
            else:
                self.cards["Battery"].config(text="N/A")
            self.cards["Uptime"].config(text=str(datetime.timedelta(seconds=int(uptime_seconds))))
            self.cards["Processes"].config(text=f"{process_count}")

            # --- Update Graphs/Meters ---
            self.cpu_meter.configure(amountused=cpu_percent_overall)
            self.mem_meter.configure(amountused=mem_info.percent)

            # Update individual CPU core meters
            if len(self.cpu_core_meters) == len(cpu_per_core_percents):
                for i, percent in enumerate(cpu_per_core_percents):
                    self.cpu_core_meters[i].configure(value=percent)
            elif self.cpu_core_meters: # If meters exist but count doesn't match, recreate them (e.g., if CPU hot-plugging occurs, though rare)
                self._create_cpu_core_meters()


            # Disk I/O: Calculate speed based on difference from previous reading
            current_disk_io = psutil.disk_io_counters()
            current_disk_read = current_disk_io.read_bytes / (1024 * 1024) # MB
            current_disk_write = current_disk_io.write_bytes / (1024 * 1024) # MB

            # Initialize previous values on first run
            if not hasattr(self, '_prev_disk_read'):
                self._prev_disk_read = current_disk_read
                self._prev_disk_write = current_disk_write
                disk_read_speed = 0
                disk_write_speed = 0
            else:
                # Calculate speed over the last 2 seconds (update_data interval)
                disk_read_speed = (current_disk_read - self._prev_disk_read) / 2
                disk_write_speed = (current_disk_write - self._prev_disk_write) / 2
                self._prev_disk_read = current_disk_read
                self._prev_disk_write = current_disk_write

            # Update Floodgauges, ensuring value doesn't exceed max
            self.disk_read_gauge.configure(value=min(disk_read_speed, self.disk_read_gauge.cget('maximum')))
            self.disk_write_gauge.configure(value=min(disk_write_speed, self.disk_write_gauge.cget('maximum')))


            # --- Update Network Tab Real-time Usage ---
            self.net_total_sent_label.config(text=f"Total Sent: {net_io.bytes_sent/1024/1024:.1f} MB")
            self.net_total_recv_label.config(text=f"Total Received: {net_io.bytes_recv/1024/1024:.1f} MB")

            # Update per-interface labels dynamically
            for widget in self.per_if_frame.winfo_children(): # Clear previous labels
                widget.destroy()

            net_io_per_if = psutil.net_io_counters(pernic=True) # Get per-interface stats
            # Initialize previous per-interface stats if not present
            if not hasattr(self, '_prev_net_io_per_if'):
                self._prev_net_io_per_if = {name: {'bytes_sent': 0, 'bytes_recv': 0}
                                            for name, stats in net_io_per_if.items()}

            for interface_name, stats in net_io_per_if.items():
                prev_stats = self._prev_net_io_per_if.get(interface_name, {'bytes_sent': 0, 'bytes_recv': 0})

                # Calculate speed in KB/s
                sent_speed = (stats.bytes_sent - prev_stats['bytes_sent']) / 2 / 1024
                recv_speed = (stats.bytes_recv - prev_stats['bytes_recv']) / 2 / 1024

                # Create and pack a label for each interface
                tb.Label(self.per_if_frame, text=f"{interface_name}: {sent_speed:.1f} KB/s ↑ / {recv_speed:.1f} KB/s ↓",
                         font=("Segoe UI", 10), bootstyle="secondary").pack(anchor=W, padx=5)

                # Store current stats for next calculation
                self._prev_net_io_per_if[interface_name] = {'bytes_sent': stats.bytes_sent, 'bytes_recv': stats.bytes_recv}


            # --- Alerts ---
            current_time = time.time()
            if current_time - self._last_alert_time > 30: # Cooldown period to prevent alert spam
                if cpu_percent_overall > self.cpu_alert_threshold.get():
                    self._show_alert(f"High CPU usage: {cpu_percent_overall:.1f}%")
                    self._last_alert_time = current_time
                if mem_info.percent > self.mem_alert_threshold.get():
                    self._show_alert(f"High Memory usage: {mem_info.percent:.1f}%")
                    self._last_alert_time = current_time
                if disk_info.percent > self.disk_alert_threshold.get():
                    self._show_alert(f"High Disk usage: {disk_info.percent:.1f}%")
                    self._last_alert_time = current_time

        except Exception as e:
            logger.error(f"Error updating data: {e}", exc_info=True)

        # Schedule the next update after 2000 milliseconds (2 seconds)
        self.root.after(2000, self.update_data)

    # --- Settings Actions ---
    def set_theme(self, theme):
        self.theme = theme
        self.style.theme_use(theme)
        logger.info(f"Theme changed to: {theme}")

    def apply_settings(self):
        # Tkinter IntVars automatically update when entry fields change,
        # so simply showing a confirmation is enough.
        messagebox.showinfo("Settings Applied", "System alert thresholds updated successfully!")
        logger.info(f"Settings applied: CPU Alert={self.cpu_alert_threshold.get()}%, Mem Alert={self.mem_alert_threshold.get()}%, Disk Alert={self.disk_alert_threshold.get()}%")

    # --- Alerts ---
    def _show_alert(self, message):
        # Using ttkbootstrap's Messagebox for better theme integration and appearance
        tb.Messagebox.show_warning(message=message, title="System Alert", parent=self.root)
        logger.warning(message)

    # --- Log File Handling ---
    def open_log_file(self):
        try:
            log_file_path = os.path.abspath(LOG_FILE)
            if os.path.exists(log_file_path):
                # Open log file based on OS
                if platform.system() == 'Windows':
                    os.startfile(log_file_path)
                elif platform.system() == 'Darwin': # macOS
                    os.system(f'open {log_file_path}')
                elif platform.system() == 'Linux':
                    os.system(f'xdg-open {log_file_path}')
                else:
                    messagebox.showinfo("Open Log File", f"Log file located at:\n{log_file_path}\n(Manual opening required for this OS)")
            else:
                messagebox.showinfo("Log File Not Found", f"Log file does not exist yet: {log_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")
            logger.error(f"Error opening log file: {e}")

    # --- Application Closing Protocol ---
    def on_closing(self):
        self.update_data_running = False # Stop the data update loop
        # Cancel any pending after calls for wellbeing timers to prevent errors
        if self.pomodoro_timer_id:
            self.root.after_cancel(self.pomodoro_timer_id)
        if self.eye_reminder_timer_id:
            self.root.after_cancel(self.eye_reminder_timer_id)
        logger.info("Application closed.")
        self.root.destroy() # Destroy the main window

# --- Custom Log Handler for GUI (to display logs in the ScrolledText widget) ---
class GuiHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(formatter) # Use the global formatter defined earlier

    def emit(self, record):
        msg = self.format(record)
        try:
            # Ensure the widget still exists before trying to update it (important during shutdown)
            if self.text_widget.winfo_exists():
                self.text_widget.configure(state='normal') # Enable writing
                self.text_widget.insert(tk.END, msg + '\n') # Insert message at the end
                self.text_widget.configure(state='disabled') # Disable writing
                self.text_widget.see(tk.END) # Scroll to the very end to show latest log
        except tk.TclError:
            # This error often occurs if the widget is destroyed between winfo_exists() and configure()
            # during application shutdown. It's safe to ignore here.
            pass
        except Exception as e:
            # Catch any other unexpected errors during log emission to prevent app crash
            print(f"Error in GuiHandler: {e}") # Print to console as a fallback

# --- Main Application Entry Point ---
if __name__ == "__main__":
    # Create the main window using ttkbootstrap.Window for themed title bar and widgets
    root = tb.Window(themename="darkly") # Start with a dark theme
    app = SystemMonitorApp(root)
    root.mainloop() # Start the Tkinter event loop