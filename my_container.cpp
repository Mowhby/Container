#include <iostream>
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <cstdlib>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <cstring>
#include <time.h>
#include <vector>
#include <unordered_map>
#include <dirent.h>

typedef struct {
    time_t container_id = 0;
    char *container_folder = nullptr;
    char *executable = nullptr;
    char *hostname = nullptr;
    long memory_limit = 67108864;  // 64 MB
    long cpu_limit = 50000;        // 50%
    int core_number = 0;
    int read_iops = 100;
    int write_iops = 50;
} ContainerConfig;

typedef struct {
    pid_t running[512];
    int running_count;
    pid_t zombie[512];
    int zombie_count;
} ContainerProcessList;


void analyze_process_status(pid_t parent_pid, pid_t pid, ContainerProcessList *plist) {
    char path[64], buffer[512];
    FILE *file;
    pid_t ppid = -1;
    char state[16] = "Unknown";

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    file = fopen(path, "r");
    if (!file) return;

    while (fgets(buffer, sizeof(buffer), file)) {
        if (strncmp(buffer, "PPid:", 5) == 0)
            sscanf(buffer, "PPid:\t%d", &ppid);
        else if (strncmp(buffer, "State:", 6) == 0)
            sscanf(buffer, "State:\t%s", state);
    }
    fclose(file);

    if (ppid == parent_pid) {
        if (state[0] == 'Z') {
            plist->zombie[plist->zombie_count++] = pid;
        } else {
            plist->running[plist->running_count++] = pid;
        }
    }
}


void gather_container_processes(pid_t manager_pid, ContainerProcessList *plist) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("[Error] Failed to open /proc");
        return;
    }

    struct dirent *entry;
    plist->running_count = 0;
    plist->zombie_count = 0;

    while ((entry = readdir(proc))) {
        if (!isdigit(entry->d_name[0])) continue;

        pid_t pid = atoi(entry->d_name);
        analyze_process_status(manager_pid, pid, plist);
    }
    closedir(proc);
}


char* allocate_stack_memory() {
    constexpr int kStackSize = 64 * 1024;  // 64KB stack
    char* stack = new (std::nothrow) char[kStackSize];

    if (!stack) {
        std::fprintf(stderr, "[Fatal] Failed to allocate stack memory.\n");
        std::exit(EXIT_FAILURE);
    }

    // Return pointer to the top of the stack (stack grows downward)
    return stack + kStackSize;
}

void initialize_environment_variables() {
    clearenv();
    // Set TERM variable
    if (setenv("TERM", "xterm-256color", 1) != 0) {
        perror("Failed to set TERM environment variable");
        exit(EXIT_FAILURE);
    }
    // Set PATH variable
    if (setenv("PATH", "/:/bin/:/sbin/:/usr/bin:/usr/sbin", 1) != 0) {
        perror("Failed to set PATH environment variable");
        exit(EXIT_FAILURE);
    }
}

void set_memory_cgroup(ContainerConfig *container_config)
{
    char command[512];

    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    system("echo +memory > /sys/fs/cgroup/cgroup.subtree_control");

    snprintf(command, sizeof(command),
             "echo %ld > /sys/fs/cgroup/%s/memory.max",
             container_config->memory_limit, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("memory.max write failed");
        exit(EXIT_FAILURE);
    }

    snprintf(command, sizeof(command),
             "echo %d > /sys/fs/cgroup/%s/cgroup.procs",
             getpid(), container_config->container_folder);
    if (system(command) == -1)
    {
        perror("cgroup.procs write failed");
        exit(EXIT_FAILURE);
    }
}

void set_cpu_cgroup(ContainerConfig *container_config)
{
    char command[512];

    // Create CPU cgroup directory
    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // Enable CPU controller in parent
    system("echo +cpu > /sys/fs/cgroup/cgroup.subtree_control");

    // Set CPU limit: quota period format (50% = 50000 / 100000)
    snprintf(command, sizeof(command),
             "echo \"%ld 100000\" > /sys/fs/cgroup/%s/cpu.max",
             container_config->cpu_limit, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("cpu.max write failed");
        exit(EXIT_FAILURE);
    }

    // Add current process to cgroup
    snprintf(command, sizeof(command),
             "echo %d > /sys/fs/cgroup/%s/cgroup.procs",
             getpid(), container_config->container_folder);
    if (system(command) == -1)
    {
        perror("cgroup.procs write failed");
        exit(EXIT_FAILURE);
    }
}

void set_IO_cgroup(ContainerConfig *container_config)
{
    char command[512];
    const char *device = "8:0";

    // Create IO cgroup directory
    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // Enable IO controller in parent
    system("echo +io > /sys/fs/cgroup/cgroup.subtree_control");

    // Set read & IOPS limit
    snprintf(command, sizeof(command),
            "echo '%s rbps=max riops=%d wbps=max wiops=%d' > /sys/fs/cgroup/%s/io.max",
            device,
            container_config->read_iops,
            container_config->write_iops,
            container_config->container_folder);
    if (system(command) == -1) {
        perror("Failed to write combined IOPS to io.max");
        exit(EXIT_FAILURE);

        // Add current process to cgroup
        snprintf(command, sizeof(command),
                "echo %d > /sys/fs/cgroup/%s/cgroup.procs",
                getpid(), container_config->container_folder);
        if (system(command) == -1)
        {
            perror("cgroup.procs write failed");
            exit(EXIT_FAILURE);
        }
    }
}

void init_container(ContainerConfig *container_config)
{
    // set cgroup limits
    set_memory_cgroup(container_config);
    set_cpu_cgroup(container_config);
    set_IO_cgroup(container_config);

    // Set CPU affinity
    int core = container_config->core_number;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pid_t pid = getpid();
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }
}

void setup_root_directory(ContainerConfig *containerConfig)
{
    char command[300];
    snprintf(command, sizeof(command), "mkdir ./containers/%s > /dev/null", containerConfig->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }
    snprintf(command, sizeof(command), "tar -xzf alpine-minirootfs-3.7.0-x86_64.tar.gz -C ./containers/%s", containerConfig->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }
    snprintf(command, sizeof(command), "sudo cp %s ./containers/%s", containerConfig->executable, containerConfig->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }    
    snprintf(command, sizeof(command), "mkdir ./containers/%s/lib/x86_64-linux-gnu", containerConfig->container_folder);
    system(command);
    snprintf(command, sizeof(command), "mkdir ./containers/%s/lib64", containerConfig->container_folder);
    system(command);
    snprintf(command, sizeof(command), "sudo cp /lib/x86_64-linux-gnu/libc.so.6 ./containers/%s/lib/x86_64-linux-gnu", containerConfig->container_folder);
    system(command);
    snprintf(command, sizeof(command), "sudo cp /lib64/ld-linux-x86-64.so.2 ./containers/%s/lib64/", containerConfig->container_folder);
    system(command);
}

int CreateContainer(void *args) {
    ContainerConfig *containerConfig = (ContainerConfig *)args;

    printf("Initializing container...\n");
    init_container(containerConfig);

    printf("Setting up root directory...\n");
    setup_root_directory(containerConfig);

    char new_root_path[300];
    snprintf(new_root_path, sizeof(new_root_path), "./containers/%s", containerConfig->container_folder);

    printf("Changing root to: %s\n", new_root_path);
    initialize_environment_variables();
    chroot(new_root_path);
    chdir("/");

    mkdir("/proc", 0555);

    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        perror("mount /proc failed");
        exit(EXIT_FAILURE);
    }

    // Set container hostname
    if (sethostname(containerConfig->hostname, strlen(containerConfig->hostname)) == -1) {
        perror("error setting hostname");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // CHILD PROCESS
        char *executable_name = basename(containerConfig->executable);
        printf("Attempting to run: /%s\n", executable_name);
        fflush(stdout);

        // Execute the program relative to new root
        execl(executable_name, executable_name, (char *)NULL);

        // If execl fails
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else {
        // PARENT
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("[parent] waitpid failed");
        } else if (WIFEXITED(status)) {
            printf("\n [parent] Child exited with code %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[parent] Child killed by signal %d (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
        } else {
            printf("[parent] Child exited abnormally\n");
        }
    }
    umount("/proc");

    return EXIT_SUCCESS;
}

void show_container_status(const std::unordered_map<int, pid_t>& pid_map, ContainerConfig configs[]) {
    ContainerProcessList list;
    gather_container_processes(getpid(), &list);
    printf("[Status] Active Containers:\n");
    for (int i = 0; i < list.running_count; ++i) {
        int idx = pid_map.at(list.running[i]);
        printf("PID: %d\tHostname: %s\n", list.running[i], configs[idx].hostname);
    }
    printf("\n");
    printf("[Status] Zombie Containers:\n");
    for (int i = 0; i < list.zombie_count; ++i) {
        int idx = pid_map.at(list.zombie[i]);
        printf("PID: %d\tHostname: %s\n", list.zombie[i], configs[idx].hostname);
    }
    printf("\n");
}

void terminate_container(pid_t pid) {
    if (kill(pid, SIGKILL) == 0) {
        printf("[Terminate] Process %d killed.\n", pid);
    } else {
        perror("[Terminate] Failed");
    }
}

void restart_container(pid_t pid, ContainerConfig configs[], int &count, std::unordered_map<int, pid_t>& pid_map) {
    int idx = pid_map[pid];
    ContainerConfig old_cfg = configs[idx];

    if (kill(pid, SIGKILL) != 0) {
        perror("[Restart] Failed to kill");
        return;
    }

    ++count;
    time_t id = time(nullptr);
    char *new_folder = (char*)malloc(256);
    snprintf(new_folder, 255, "folder_%ld", id);

    configs[count - 1] = {
        old_cfg.container_id,
        new_folder,
        old_cfg.executable,
        old_cfg.hostname,
        old_cfg.memory_limit,
        old_cfg.cpu_limit,
        old_cfg.core_number,
        old_cfg.read_iops,
        old_cfg.write_iops
    };

    pid_t new_pid = clone(CreateContainer, allocate_stack_memory(), CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, (void *)&configs[count - 1]);
    printf("[Restart] Replaced PID %d with PID %d (Hostname: %s)\n", pid, new_pid, old_cfg.hostname);
    pid_map[new_pid] = count - 1;
}

void wait_for_containers(int count) {
    printf("[Wait] Waiting for containers to finish...\n");
    for (int i = 0; i < count; ++i) {
        wait(nullptr);
    }
}

void parse_cli_args(int argc, char *argv[], ContainerConfig *configs) {
    int opt;
    int current = -1;

    while ((opt = getopt(argc, argv, "x:n:m:u:i:o:")) != -1) {
        switch (opt) {
            case 'x': {  // Executable
                current++;
                configs[current].container_id = time(NULL);

                char *folder = (char *)malloc(200);
                snprintf(folder, 200, "folder_%ld", (long)configs[current].container_id);
                configs[current].container_folder = folder;

                configs[current].executable = optarg;
                configs[current].hostname = NULL;  // Initialize to NULL
                break;
            }

            case 'n': {  // Hostname
                if (current >= 0) {
                    configs[current].hostname = optarg;
                } else {
                    fprintf(stderr, "[Error] --hostname (-n) must follow an executable (-x)\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            case 'm': {  // Memory limit
                if (current >= 0) {
                    configs[current].memory_limit = strtol(optarg, nullptr, 10);
                } else {
                    fprintf(stderr, "[Error] --memory (-m) must follow an executable (-x)\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            case 'u': {  // CPU quota
                if (current >= 0) {
                    configs[current].cpu_limit = strtol(optarg, nullptr, 10);
                } else {
                    fprintf(stderr, "[Error] --cpu (-u) must follow an executable (-x)\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            case 'i': {  // Read IOPS
                if (current >= 0) {
                    configs[current].read_iops = atoi(optarg);
                } else {
                    fprintf(stderr, "[Error] --read-iops (-i) must follow an executable (-x)\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            case 'o': {  // Write IOPS
                if (current >= 0) {
                    configs[current].write_iops = atoi(optarg);
                } else {
                    fprintf(stderr, "[Error] --write-iops (-o) must follow an executable (-x)\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            default: {
                fprintf(stderr, "Usage:\n");
                fprintf(stderr, "  %s -x <executable> [-n <hostname>] [-m <mem>] [-u <cpu>] [-i <read-iops>] [-o <write-iops>] ...\n", argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("[Manager] PID %d started.\n", getpid());

    long core_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (core_count == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    std::vector<char*> container_dirs;
    ContainerConfig configs[20];
    int container_count = 0;
    std::unordered_map<int, pid_t> pid_to_index;

    parse_cli_args(argc, argv, configs);

    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid_t pid = clone(CreateContainer, allocate_stack_memory(), flags, (void *)&configs[0]);
    printf("[Manager] Container started (PID: %d, Hostname: %s)\n", pid, configs[0].hostname);
    pid_to_index[pid] = 0;


    char input[256];
    while (1) {
        printf("[Command] Enter [status, terminate <PID>, restart <PID>, exit]: ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "status") == 0) {
            show_container_status(pid_to_index, configs);
        } else if (strncmp(input, "terminate", 9) == 0) {
            pid_t pid = atoi(input + 10);
            terminate_container(pid);
        } else if (strncmp(input, "restart", 7) == 0) {
            pid_t pid = atoi(input + 8);
            restart_container(pid, configs, container_count, pid_to_index);
        } else if (strcmp(input, "exit") == 0) {
            break;
        } else {
            printf("[Error] Unknown command.\n");
        }
    }

    wait_for_containers(container_count);
    printf("[Manager] Shutdown complete.\n");
    return EXIT_SUCCESS;
}


// "I collaborated with my classmate Omid Heydari on this code."