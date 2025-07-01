from bcc import BPF
from datetime import datetime

LOG_FILE = "ebpf_log.txt"

syscalls = ["clone", "mount", "mkdir"]
bpf_program = """
#include <uapi/linux/ptrace.h>
"""

for syscall in syscalls:
    bpf_program += f"""
int trace_{syscall}(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("PID %d called syscall {syscall}\\n", pid);
    return 0;
}}
"""

b = BPF(text=bpf_program)
for syscall in syscalls:
    try:
        b.attach_kprobe(event="__x64_sys_" + syscall, fn_name=f"trace_{syscall}")
    except Exception as e:
        print(f"[!] Could not attach to syscall {syscall}: {e}")

print("Starting EBPF...")

with open(LOG_FILE, "a") as log_file:
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] {msg}\n"
            print(line.strip())
            log_file.write(line)
            log_file.flush()
        except KeyboardInterrupt:
            print("Stopped.")
            break
        except ValueError:
            continue
