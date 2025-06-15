<h1>Welcome to Your Advanced System Dashboard & Wellbeing Guide!</h1>
<p>Hey there! Welcome to the guide for the <strong>Advanced System Dashboard & Wellbeing</strong> application. This nifty tool is designed to keep an eye on your computer's performance and help you maintain your wellbeing while you work. Let's dive into what this app can do for you!</p>

<h2>What Can This App Do?</h2>

<h3>System Monitoring</h3>
    <ul>
        <li><strong>CPU Usage:</strong> Keep track of how much your CPU is being used, overall and per core.</li>
        <li><strong>Memory Usage:</strong> Monitor your RAM and swap memory usage.</li>
        <li><strong>Disk Usage:</strong> Check out how much of your disk is being used and the I/O operations.</li>
        <li><strong>Network I/O:</strong> See how much data is being sent and received over your network.</li>
        <li><strong>Battery Status:</strong> Keep an eye on your battery percentage and charging status.</li>
        <li><strong>Uptime:</strong> Find out how long your system has been running.</li>
        <li><strong>CPU Temperature:</strong> Monitor your CPU temperature to keep things cool.</li>
        <li><strong>Processes:</strong> Get a list of all running processes with details like PID, name, CPU usage, and more.</li>
    </ul>

<h3>Wellbeing Features</h3>
    <ul>
        <li><strong>Pomodoro Timer:</strong> Manage your work and break intervals to boost productivity.</li>
        <li><strong>Eye Strain Reminder:</strong> Get reminders to take breaks and reduce eye strain using the 20-20-20 rule.</li>
    </ul>

<h3>User Interface</h3>
    <ul>
        <li><strong>Dashboard:</strong> Get an overview of your system metrics.</li>
        <li><strong>System Info:</strong> Dive into detailed system information.</li>
        <li><strong>Processes:</strong> View and manage running processes.</li>
        <li><strong>Network:</strong> Monitor network interface details and real-time usage.</li>
        <li><strong>Logs:</strong> View application logs and manage log files.</li>
        <li><strong>Wellbeing:</strong> Configure and use the Pomodoro timer and eye strain reminders.</li>
        <li><strong>System Actions:</strong> Perform system actions like shutdown, restart, and logout.</li>
        <li><strong>Settings:</strong> Change application settings and set alert thresholds.</li>
    </ul>

<h2>Getting Started</h2>

<h3>Requirements</h3>
   <p>To run this application, you'll need:</p>
    <ul>
        <li>Python 3.x</li>
        <li>Libraries: <code>ttkbootstrap</code>, <code>psutil</code>, <code>tkinter</code>, <code>matplotlib</code></li>
    </ul>

  <h3>Installation</h3>
    <ol>
        <li>
            <p><strong>Clone the Repository:</strong><br>
            Open your terminal and run:</p>
            <pre><code>git clone &lt;[repository_url](https://github.com/radiushere/SystemMonitorApp)&gt;
cd &lt;repository_directory&gt;</code></pre>
        </li>
        <li>
            <p><strong>Install Dependencies:</strong><br>
            Make sure you have Python installed. Then, install the required libraries using pip:</p>
            <pre><code>pip install ttkbootstrap psutil matplotlib</code></pre>
        </li>
    </ol>

  <h3>Using the Application</h3>
    <ol>
        <li>
            <p><strong>Run the Application:</strong><br>
            Navigate to the directory containing the script and run:</p>
            <pre><code>python system_monitor.py</code></pre>
        </li>
        <li>
            <p><strong>Using the Application:</strong></p>
            <ul>
                <li><strong>Dashboard Tab:</strong> View real-time system metrics.</li>
                <li><strong>System Info Tab:</strong> Get detailed information about your system.</li>
                <li><strong>Processes Tab:</strong> View and manage running processes.</li>
                <li><strong>Network Tab:</strong> Monitor network interface details and usage.</li>
                <li><strong>Logs Tab:</strong> View application logs and manage log files.</li>
                <li><strong>Wellbeing Tab:</strong> Configure and use the Pomodoro timer and eye strain reminders.</li>
                <li><strong>System Actions Tab:</strong> Perform system actions like shutdown, restart, and logout.</li>
                <li><strong>Settings Tab:</strong> Change application settings and set alert thresholds.</li>
            </ul>
        </li>
    </ol>

  <h2>Configuration</h2>

  <h3>Themes</h3>
    <p>You can change the application theme in the settings tab to suit your style.</p>

  <h3>Alert Thresholds</h3>
    <p>Set custom alert thresholds for CPU, memory, and disk usage to get notified when things get too heated.</p>

  <h3>Pomodoro Timer</h3>
    <p>Configure your work, short break, and long break durations to fit your workflow.</p>

  <h3>Eye Strain Reminder</h3>
    <p>Set the reminder interval for eye strain alerts to keep your eyes fresh and relaxed.</p>

  <h2>Logging</h2>
    <p>The application logs all events and actions to a log file named <code>system_monitor_gui.log</code>. You can view and manage logs in the Logs tab to keep track of what's been happening.</p>
