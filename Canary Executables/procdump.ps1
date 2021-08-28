Write-Output "
ProcDump v8.2 - Sysinternals process dump utility
Copyright (C) 2009-2016 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

Monitors a process and writes a dump file when the process exceeds the
specified criteria or has an exception.

Capture Usage:
   procdump.exe [-ma | -mp | -d Callback_DLL] [-64]
                [-n Count]
                [-s Seconds]
                [-c|-cl CPU_Usage [-u]]
                [-m|-ml Commit_Usage]
                [-p|-pl Counter_Threshold]
                [-h]
                [-e [1 [-g] [-b]]]
                [-l]
                [-t]
                [-f  Include_Filter, ...]
                [-fx Exclude_Filter, ...]
                [-o]
                [-r [1..5] [-a]]
                {
                 {{[-w] Process_Name | Service_Name | PID} [Dump_File | Dump_Folder] }
                |
                 {-x Dump_Folder Image_File [Argument, ...]}
                }
                [-wer]
Install Usage:
   procdump.exe -i [Dump_Folder]
                [-kill]
                [-wer]
                [-ma | -mp | -d Callback_DLL]
Uninstall Usage:
   procdump.exe -u

Options:
   -a      Avoid outage. Requires -r. If the trigger will cause the target
           to suspend for a prolonged time due to an exceeded concurrent
           dump limit, the trigger will be skipped.
   -b      Treat debug breakpoints as exceptions (otherwise ignore them).
   -c      CPU threshold above which to create a dump of the process.
   -cl     CPU threshold below which to create a dump of the process.
   -d      Invoke the minidump callback routine named MiniDumpCallbackRoutine
           of the specified DLL.
   -e      Write a dump when the process encounters an unhandled exception.
           Include the 1 to create dump on first chance exceptions.
   -f      Filter (include) on the content of exceptions and debug logging.
           Wildcards (*) are supported.
   -fx     Filter (exclude) on the content of exceptions and debug logging.
           Wildcards (*) are supported.
   -g      Run as a native debugger in a managed process (no interop).
   -h      Write dump if process has a hung window (does not respond to
           window messages for at least 5 seconds).
   -i      Install ProcDump as the AeDebug postmortem debugger.
           Only -ma, -mp, -d and -r are supported as additional options.
           Uninstall (-u only) restores the previous configuration.
   -kill   Terminates the process after generating the dump, rather than
           letting the exception get caught by Windows Error Reporting.
   -l      Display the debug logging of the process.
   -m      Memory commit threshold in MB at which to create a dump.
   -ml     Trigger when memory commit drops below specified MB value.
   -ma     Write a dump file with all process memory. The default
           dump format only includes thread and handle information.
   -mp     Write a dump file with thread and handle information, and all
           read/write process memory. To minimize dump size, memory areas
           larger than 512MB are searched for, and if found, the largest
           area is excluded. A memory area is the collection of same
           sized memory allocation areas. The removal of this (cache)
           memory reduces Exchange and SQL Server dumps by over 90%.
   -n      Number of dumps to write before exiting.
   -o      Overwrite an existing dump file.
   -p      Trigger on the specified performance counter when the threshold
           is exceeded. Note: to specify a process counter when there are
           multiple instances of the process running, use the process ID
           with the following syntax: "\Process(<name>_<pid>)\counter"
   -pl     Trigger when performance counter falls below the specified value.
   -r      Dump using a clone. Concurrent limit is optional (default 1, max 5).
           CAUTION: a high concurrency value may impact system performance.
           - Windows 7   : Uses Reflection. OS doesn't support -e.
           - Windows 8.0 : Uses Reflection. OS doesn't support -e.
           - Windows 8.1+: Uses PSS. All trigger types are supported.
   -s      Consecutive seconds before dump is written (default is 10).
   -t      Write a dump when the process terminates.
   -u      Treat CPU usage relative to a single core (used with -c).
           As the only option, Uninstalls ProcDump as the postmortem debugger.
   -w      Wait for the specified process to launch if it's not running.
   -wer    Queue the dump files to WER (Windows Error Reporting).
   -x      Launch the specified image with optional arguments.
           If it is a Store Application or Package, ProcDump will start
           on the next activation (only).
   -64     By default ProcDump will capture a 32-bit dump of a 32-bit process
           when running on 64-bit Windows. This option overrides to create a
           64-bit dump. Only use for WOW64 subsystem debugging.

License Agreement:
   Use the -accepteula command line option to automatically accept the
   Sysinternals license agreement.

Automated Termination:
   Setting an event with the name "procdump-<PID>" is the same as typing Ctrl+C
   to gracefully terminate ProcDump.

Filename:
   Default dump filename: PROCESSNAME_YYMMDD_HHMMSS.dmp
   The following substitutions are supported:
           PROCESSNAME   Process Name
           PID           Process ID
           EXCEPTIONCODE Exception Code
           YYMMDD        Year/Month/Day
           HHMMSS        Hour/Minute/Second

Examples:
   Use -? -e to see example command lines.
"