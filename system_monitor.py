import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import psutil
import threading
import time
import logging
import datetime
import os

# --- Configuration ---
LOG_FILE = 'system_monitor_gui.log'
UPDATE_INTERVAL = 2000  # milliseconds (e.g., 2 seconds)
BREAK_REMINDER_DEFAULT_MINUTES = 25
TOP_PROCESS_COUNT = 3

# --- Logging Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(LOG_FILE)
# Define formatter here to be accessible by GuiHandler as well
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class GuiHandler(logging.Handler):
    """Custom logging handler to display logs in a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(formatter) # Use the globally defined formatter

    def emit(self, record):
        msg = self.format(record)
        try:
            if self.text_widget.winfo_exists(): # Check if widget still exists
                self.text_widget.configure(state='normal')
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.configure(state='disabled')
                self.text_widget.see(tk.END) # Scroll to the end
        except tk.TclError:
            # Handle cases where widget might be destroyed during shutdown
            pass

class SystemMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Performance & Wellbeing Monitor")
        self.root.geometry("800x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.previous_disk_io = psutil.disk_io_counters(perdisk=False) # System-wide
        if os.name == 'nt': # Windows
            self.root_partition = 'C:\\' # Common, but might need adjustment
        else: # POSIX
            self.root_partition = '/'


        # --- Styling ---
        self.style = ttk.Style()
        self.style.theme_use('clam') # or 'alt', 'default', 'classic'
        # For ttk.Frame, background is part of the style definition, not a constructor kwarg
        self.style.configure("Seccion.TFrame", background="#f0f0f0", relief="groove", borderwidth=2)
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("Title.TLabel", font=("Arial", 12, "bold"), background="#f0f0f0") # Ensure title label also has bg
        self.style.configure("Red.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='red')
        self.style.configure("Green.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='green')
        self.style.configure("Blue.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='blue')


        # --- Main Layout ---
        self.main_notebook = ttk.Notebook(root)

        # Performance Tab
        self.performance_tab = ttk.Frame(self.main_notebook, padding=10)
        self.main_notebook.add(self.performance_tab, text='Performance')
        self._create_performance_widgets(self.performance_tab)

        # Logs Tab
        self.logs_tab = ttk.Frame(self.main_notebook, padding=10)
        self.main_notebook.add(self.logs_tab, text='Logs')
        self._create_logs_widgets(self.logs_tab)

        # Wellbeing Tab
        self.wellbeing_tab = ttk.Frame(self.main_notebook, padding=10)
        self.main_notebook.add(self.wellbeing_tab, text='Digital Wellbeing')
        self._create_wellbeing_widgets(self.wellbeing_tab)

        self.main_notebook.pack(expand=True, fill='both')

        # Initial data fetch and start update loop
        self.update_data_running = True # Flag to control update loop
        self.update_data()
        logger.info("Application started.")

    def _create_section_frame(self, parent, title_text):
        # Use the styled TFrame
        frame = ttk.Frame(parent, padding=10, style="Seccion.TFrame")
        title_label = ttk.Label(frame, text=title_text, style="Title.TLabel")
        title_label.pack(pady=(0,5), anchor="w")
        return frame

    def _create_performance_widgets(self, parent_frame):
        # --- CPU ---
        cpu_frame = self._create_section_frame(parent_frame, "CPU Usage")
        cpu_frame.pack(fill="x", pady=5)

        self.cpu_overall_label = ttk.Label(cpu_frame, text="Overall CPU: 0.0%")
        self.cpu_overall_label.pack(anchor="w")
        self.cpu_overall_progress = ttk.Progressbar(cpu_frame, length=200, mode='determinate', style="Blue.Horizontal.TProgressbar")
        self.cpu_overall_progress.pack(fill="x", pady=2)

        # This frame will inherit background from its parent cpu_frame (Seccion.TFrame)
        # or use default ttk.Frame styling if not nested directly in a styled one.
        # The labels within it are styled via "TLabel".
        self.per_core_frame = ttk.Frame(cpu_frame) # CORRECTED: Removed background option
        self.per_core_frame.pack(fill="x", pady=5)
        self.per_core_labels = []
        self.per_core_progressbars = []

        num_cores = psutil.cpu_count(logical=True)
        for i in range(num_cores):
            # Labels will use "TLabel" style which includes background #f0f0f0
            core_label = ttk.Label(self.per_core_frame, text=f"Core {i+1}: 0.0%")
            core_label.grid(row=i, column=0, sticky="w", padx=5)
            core_progress = ttk.Progressbar(self.per_core_frame, length=150, mode='determinate', style="Green.Horizontal.TProgressbar")
            core_progress.grid(row=i, column=1, sticky="ew", padx=5)
            self.per_core_labels.append(core_label)
            self.per_core_progressbars.append(core_progress)
        self.per_core_frame.grid_columnconfigure(1, weight=1)


        # --- Memory ---
        mem_frame = self._create_section_frame(parent_frame, "Memory Usage")
        mem_frame.pack(fill="x", pady=5)

        self.mem_label = ttk.Label(mem_frame, text="Memory: 0.0 GB / 0.0 GB (0.0%)")
        self.mem_label.pack(anchor="w")
        self.mem_progress = ttk.Progressbar(mem_frame, length=200, mode='determinate', style="Red.Horizontal.TProgressbar")
        self.mem_progress.pack(fill="x", pady=2)

        # --- Disk I/O ---
        disk_frame = self._create_section_frame(parent_frame, f"Disk I/O ({self.root_partition})")
        disk_frame.pack(fill="x", pady=5)
        self.disk_io_label = ttk.Label(disk_frame, text="Read: 0.0 MB/s, Write: 0.0 MB/s")
        self.disk_io_label.pack(anchor="w")

        # --- Top Processes ---
        process_frame = self._create_section_frame(parent_frame, "Top Processes by CPU")
        process_frame.pack(fill="x", pady=5)
        # Using tk.Text for multiline, fixed-width like display. Styling it a bit.
        self.process_text = tk.Text(process_frame, height=5, width=60, state="disabled", relief="sunken", borderwidth=1, background="#fafafa", font=("Courier New", 9), wrap=tk.WORD)
        self.process_text.pack(fill="x", expand=True)


    def _create_logs_widgets(self, parent_frame):
        log_display_frame = self._create_section_frame(parent_frame, "Application & System Logs")
        log_display_frame.pack(expand=True, fill='both', pady=5)

        self.log_text_area = scrolledtext.ScrolledText(log_display_frame, state='disabled', height=15, relief="sunken", borderwidth=1, font=("Courier New", 9), wrap=tk.WORD)
        self.log_text_area.pack(expand=True, fill='both')

        # Add the custom handler to the logger
        gui_log_handler = GuiHandler(self.log_text_area)
        logger.addHandler(gui_log_handler)

        open_log_button = ttk.Button(log_display_frame, text="Open Log File", command=self.open_log_file)
        open_log_button.pack(pady=5, anchor="center")


    def _create_wellbeing_widgets(self, parent_frame):
        # --- Uptime ---
        uptime_frame = self._create_section_frame(parent_frame, "System Uptime")
        uptime_frame.pack(fill="x", pady=5)
        self.uptime_label = ttk.Label(uptime_frame, text="Uptime: Calculating...")
        self.uptime_label.pack(anchor="w")

        # --- Break Reminder ---
        break_frame = self._create_section_frame(parent_frame, "Break Reminder")
        break_frame.pack(fill="x", pady=5)

        self.break_minutes_var = tk.IntVar(value=BREAK_REMINDER_DEFAULT_MINUTES)
        
        reminder_controls_frame = ttk.Frame(break_frame, style="Seccion.TFrame") # Use styled frame for consistent bg
        reminder_controls_frame.pack(fill="x")

        ttk.Label(reminder_controls_frame, text="Remind me every (minutes):").pack(side=tk.LEFT, padx=(0,5))
        self.break_interval_entry = ttk.Entry(reminder_controls_frame, textvariable=self.break_minutes_var, width=5)
        self.break_interval_entry.pack(side=tk.LEFT, padx=5)

        self.start_break_button = ttk.Button(reminder_controls_frame, text="Start Break Timer", command=self.start_break_timer)
        self.start_break_button.pack(side=tk.LEFT, padx=5)
        
        self.break_timer_label = ttk.Label(reminder_controls_frame, text="") # Will be updated
        self.break_timer_label.pack(side=tk.LEFT, padx=10, expand=True, fill='x')


        self.break_timer_active = False
        self.break_end_time = None
        self.break_timer_id = None # To store the ID from root.after for the break timer


    def update_data(self):
        if not self.update_data_running: # Stop updates if flag is false
            return
        try:
            # CPU
            cpu_overall = psutil.cpu_percent(interval=None)
            self.cpu_overall_label.config(text=f"Overall CPU: {cpu_overall:.1f}%")
            self.cpu_overall_progress['value'] = cpu_overall

            cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
            for i, core_usage in enumerate(cpu_per_core):
                if i < len(self.per_core_labels): # Check if widgets exist
                    self.per_core_labels[i].config(text=f"Core {i+1}: {core_usage:.1f}%")
                    self.per_core_progressbars[i]['value'] = core_usage

            # Memory
            mem = psutil.virtual_memory()
            self.mem_label.config(text=f"Memory: {mem.used / (1024**3):.2f} GB / {mem.total / (1024**3):.2f} GB ({mem.percent}%)")
            self.mem_progress['value'] = mem.percent

            # Disk I/O
            current_disk_io = psutil.disk_io_counters(perdisk=False)
            if self.previous_disk_io: # Ensure previous_disk_io is not None
                read_bytes_diff = current_disk_io.read_bytes - self.previous_disk_io.read_bytes
                write_bytes_diff = current_disk_io.write_bytes - self.previous_disk_io.write_bytes
                self.previous_disk_io = current_disk_io
                read_mb_s = (read_bytes_diff / (1024**2)) / (UPDATE_INTERVAL / 1000.0)
                write_mb_s = (write_bytes_diff / (1024**2)) / (UPDATE_INTERVAL / 1000.0)
                self.disk_io_label.config(text=f"Read: {read_mb_s:.2f} MB/s, Write: {write_mb_s:.2f} MB/s")
            else:
                self.previous_disk_io = current_disk_io # Initialize on first run

            # Uptime
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_str = str(datetime.timedelta(seconds=int(uptime_seconds)))
            self.uptime_label.config(text=f"Uptime: {uptime_str}")

            # Top Processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            top_processes = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:TOP_PROCESS_COUNT]
            
            process_info_str = "PID\tCPU%\tUser\t\tName\n" + "="*60 + "\n"
            for p in top_processes:
                username = p['username'] if p['username'] else 'N/A'
                process_info_str += f"{p['pid']}\t{p['cpu_percent']:.1f}%\t{username[:10]}\t\t{p['name'][:25]}\n"
            
            if self.process_text.winfo_exists():
                self.process_text.configure(state='normal')
                self.process_text.delete(1.0, tk.END)
                self.process_text.insert(tk.END, process_info_str)
                self.process_text.configure(state='disabled')


            # Break Timer Update
            if self.break_timer_active and self.break_end_time:
                remaining_time = self.break_end_time - time.time()
                if remaining_time <= 0:
                    self.break_timer_label.config(text="Time for a break!")
                    messagebox.showinfo("Break Time!", "Time to take a break and stretch!")
                    self.reset_break_timer_state() # Also resets button text
                else:
                    mins, secs = divmod(int(remaining_time), 60)
                    self.break_timer_label.config(text=f"Break in: {mins:02d}:{secs:02d}")
            
        except Exception as e:
            logger.error(f"Error in update_data: {e}", exc_info=True)
            # Optionally, display a subtle error in the GUI status bar if you add one

        finally:
            if self.update_data_running and self.root.winfo_exists():
                 # Schedule next update only if running and root exists
                self.root.after(UPDATE_INTERVAL, self.update_data)


    def start_break_timer(self):
        if self.break_timer_active: # If timer is running, treat as reset
            if self.break_timer_id: # Cancel any pending after() call for the break timer
                self.root.after_cancel(self.break_timer_id)
            self.reset_break_timer_state() # This will also change button text
            return

        try:
            minutes = self.break_minutes_var.get()
            if minutes <= 0:
                messagebox.showwarning("Invalid Input", "Break interval must be positive.")
                return
            self.break_end_time = time.time() + minutes * 60
            self.break_timer_active = True
            self.start_break_button.config(text="Reset Timer") # Change button text
            logger.info(f"Break timer started for {minutes} minutes.")
            # The main update_data loop will handle the countdown display and alert.
            # No separate self.root.after needed here for the break logic itself.
        except tk.TclError:
            messagebox.showwarning("Invalid Input", "Please enter a valid number for minutes.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not start timer: {e}")
            logger.error(f"Error starting break timer: {e}")

    def reset_break_timer_state(self):
        self.break_timer_active = False
        self.break_end_time = None
        if self.break_timer_id: # If an explicit break timer 'after' call was stored
             self.root.after_cancel(self.break_timer_id)
        self.break_timer_id = None
        if self.break_timer_label.winfo_exists():
            self.break_timer_label.config(text="")
        if self.start_break_button.winfo_exists():
            self.start_break_button.config(text="Start Break Timer")


    def open_log_file(self):
        try:
            log_file_path = os.path.abspath(LOG_FILE)
            if not os.path.exists(log_file_path):
                messagebox.showinfo("Log File", "Log file does not exist yet. It will be created when logs are written.")
                return

            if os.name == 'nt': # Windows
                os.startfile(log_file_path)
            elif os.uname().sysname == 'Darwin': # macOS
                os.system(f'open "{log_file_path}"')
            else: # Linux and other POSIX
                os.system(f'xdg-open "{log_file_path}"')
            logger.info(f"Attempted to open log file: {log_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")
            logger.error(f"Failed to open log file: {e}")


    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the System Monitor?"):
            logger.info("Application closing.")
            self.update_data_running = False # Stop the update loop
            
            # Cancel any pending .after() calls to prevent errors after destroy
            if hasattr(self, 'break_timer_id') and self.break_timer_id:
                self.root.after_cancel(self.break_timer_id)
            
            # It's good practice to iterate over all .after() jobs and cancel them
            # However, a simpler way for this app is to ensure the main update loop stops.
            # For more complex apps, you might need to track all .after() IDs.

            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemMonitorApp(root)
    root.mainloop()
