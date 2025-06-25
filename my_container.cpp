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
#define REMOVE_CONTAINER_FOLDER_AFTER_DEATH 0
#define MAX_CHILDREN 1024
#define IPC 0


typedef struct {
    pid_t running[MAX_CHILDREN];
    int running_count;
    pid_t zombie[MAX_CHILDREN];
    int zombie_count;
} ProcessesStatus;

typedef struct {
    time_t container_id;
    char *container_folder;
    char *executable;
    char *hostname;
    long memory_limit;
    long cpu_limit;
    int core_number;
    int read_iops;
    int write_iops;
} ContinerDetail;

void parse_arguments(int argc, char *argv[], ContinerDetail *containers, int *num_containers) {
    int option;
    int container_index = -1;

    // Parse command line arguments
    while ((option = getopt(argc, argv, "e:h:m:c:r:w:")) != -1) {
        switch (option) {
            case 'e': {  // Executable file 
                container_index++;
                containers[container_index].container_id = time(NULL);
                char *container_folder = (char *)malloc(200 * sizeof(char));
                snprintf(container_folder, 200, "folder_%ld", (long)containers[container_index].container_id);
                containers[container_index].container_folder = container_folder;
                containers[container_index].executable = optarg;
                containers[container_index].hostname = NULL;  // Initialize hostname to NULL
                sleep(2);
                break;
            }

            case 'h': {  // Hostname for the container
                if (container_index >= 0) {
                    containers[container_index].hostname = optarg;
                } else {
                    fprintf(stderr, "Error: Hostname specified without executable.\n");
                    exit(1);
                }
                break;
            }

            case 'm': { // memory limit
                if (container_index >= 0) {
                    containers[container_index].memory_limit = strtol(optarg, nullptr, 10);
                } else {
                    fprintf(stderr, "Error: memory limit specified without executable.\n");
                    exit(1);
                }
                break;
            }

            case 'c': { // cpu limit
                if (container_index >= 0) {
                    containers[container_index].cpu_limit = strtol(optarg, nullptr, 10);
                } else {
                    fprintf(stderr, "Error: cpu limit specified without executable.\n");
                    exit(1);
                }
                break;
            }
            
            case 'r': {
                if (container_index >= 0) {
                    containers[container_index].read_iops = atoi(optarg);
                } else {
                    fprintf(stderr, "Error: read_iops limit specified without executable.\n");
                    exit(1);
                }
                break;
            }

            case 'w': {
                if (container_index >= 0) {
                    containers[container_index].write_iops = atoi(optarg);
                } else {
                    fprintf(stderr, "Error: write_iops limit specified without executable.\n");
                    exit(1);
                }
                break;
            }

            default: {
                fprintf(stderr, "Usage: %s [-e executable] [-h hostname] [-m memory limit] [-c cpu limit]\n", argv[0]);
                exit(1);
            }
        }
    }

    *num_containers = container_index + 1;
}

char* stack_memory() {
    const int stackSize = 65536;
    auto *stack = new (std::nothrow) char[stackSize];

    if (stack == nullptr) { 
        printf("Cannot allocate memory \n");
        exit(EXIT_FAILURE);
    }  

    return stack+stackSize;
}

void setup_variables() {
    clearenv();
    setenv("TERM", "xterm-256color", 0);
    setenv("PATH", "/:/bin/:/sbin/:usr/bin:/usr/sbin", 0);
}

void setup_root(const char* folder){
    chroot(folder);
    chdir("/");
}

void set_memory_cgroup(ContinerDetail *container_config)
{
    char command[512];

    // Create cgroup v2 folder
    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // Enable memory controller in parent if not already done
    // system("echo +memory > /sys/fs/cgroup/cgroup.subtree_control");

    // Set memory limit using cgroup v2's memory.max
    snprintf(command, sizeof(command),
             "echo %ld > /sys/fs/cgroup/%s/memory.max",
             container_config->memory_limit, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("memory.max write failed");
        exit(EXIT_FAILURE);
    }

    // Assign current process to the cgroup
    snprintf(command, sizeof(command),
             "echo %d > /sys/fs/cgroup/%s/cgroup.procs",
             getpid(), container_config->container_folder);
    if (system(command) == -1)
    {
        perror("cgroup.procs write failed");
        exit(EXIT_FAILURE);
    }
}

void set_cpu_cgroup(ContinerDetail *container_config)
{
    char command[512];

    Create CPU cgroup directory
    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }
    // Enable CPU controller in parent
    int r = system("echo +cpu > tee /sys/fs/cgroup/cgroup.subtree_control > /dev/null");
    if (r!=0){
    printf("$$$");
    fflush(stdout);
    }
    printf("%d",r);
    fflush(stdout);
    // Set CPU limit: quota period format (50% = 50000 / 100000)
    snprintf(command, sizeof(command),
             "echo \"%ld 100000\" > /sys/fs/cgroup/%s/cpu.max",
             container_config->cpu_limit, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("cpu.max write failed");
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

void set_IO_cgroup(ContinerDetail *container_config)
{
    char command[512];
    const char *device = "8:0"; // Update if using another device

    // Create IO cgroup directory
    snprintf(command, sizeof(command), "mkdir -p /sys/fs/cgroup/%s", container_config->container_folder);
    if (system(command) == -1)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // Enable IO controller in parent
    system("echo +io > /sys/fs/cgroup/cgroup.subtree_control");

    // Set read IOPS limit
    snprintf(command, sizeof(command),
             "echo '%s rbps=max riops=%d wbps=max wiops=max' > /sys/fs/cgroup/%s/io.max",
             device, container_config->read_iops, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("io.max (read) write failed");
        exit(EXIT_FAILURE);
    }

    // Set write IOPS limit
    snprintf(command, sizeof(command),
             "echo '%s rbps=max riops=max wbps=max wiops=%d' > /sys/fs/cgroup/%s/io.max",
             device, container_config->write_iops, container_config->container_folder);
    if (system(command) == -1)
    {
        perror("io.max (write) write failed");
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

void init_container(ContinerDetail *container_config)
{
    set_cpu_cgroup(container_config);
    set_IO_cgroup(container_config);
    set_memory_cgroup(container_config);
    int core = container_config->core_number;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pid_t pid = getpid();
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }
    printf("aaaaaa");
    fflush(stdout);
}

void setup_root_directory(ContinerDetail *jailArgs)
{
    char command[300];
    snprintf(command, sizeof(command), "mkdir ./containers/%s > /dev/null", jailArgs->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }
    snprintf(command, sizeof(command), "mkdir ./containers/%s/lib/x86_64-linux-gnu", jailArgs->container_folder);
    system(command);
    snprintf(command, sizeof(command), "mkdir ./containers/%s/lib64", jailArgs->container_folder);
    system(command);
    snprintf(command, sizeof(command), "sudo cp /lib/x86_64-linux-gnu/libc.so.6 ./containers/%s/lib/x86_64-linux-gnu", jailArgs->container_folder);
    system(command);
    snprintf(command, sizeof(command), "sudo cp /lib64/ld-linux-x86-64.so.2 ./containers/%s/lib64/", jailArgs->container_folder);
    system(command);
    snprintf(command, sizeof(command), "tar -xzf alpine-minirootfs-3.7.0-x86_64.tar.gz -C ./containers/%s", jailArgs->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }
    snprintf(command, sizeof(command), "sudo cp %s ./containers/%s", jailArgs->executable, jailArgs->container_folder);
    if (system(command) == -1){
        perror("system failed");
        exit(EXIT_FAILURE);
    }    
}

int Cont(void *args) {
    ContinerDetail *jailArgs = (ContinerDetail *)args;

    printf("Initializing container...\n");
    init_container(jailArgs);

    printf("Setting up root directory...\n");
    setup_root_directory(jailArgs);

    char new_root_path[300];
    snprintf(new_root_path, sizeof(new_root_path), "./containers/%s", jailArgs->container_folder);

    printf("Changing root to: %s\n", new_root_path);
    setup_variables();
    setup_root(new_root_path);

    mkdir("/proc", 0555);

    printf("Mounting /proc...\n");
    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        perror("mount /proc failed");
        exit(EXIT_FAILURE);
    }

    // Set hostname
    if (sethostname(jailArgs->hostname, strlen(jailArgs->hostname)) == -1) {
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
        char *executable_name = basename(jailArgs->executable);
        printf("Attempting to run: /%s\n", executable_name);
        fflush(stdout);

        // Execute the program relative to new root
        execl(executable_name, executable_name, (char *)NULL);

        // If execl fails
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else {
        // PARENT PROCESS
        int status;
        wait(&status);

        if (WIFEXITED(status)) {
            printf("Child exited with code %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child killed by signal %d\n", WTERMSIG(status));
        } else {
            printf("Child exited abnormally\n");
        }
    }

    printf("Cleaning up...\n");
    umount("/proc");

    return EXIT_SUCCESS;
}

void FindStatus(pid_t parent_pid, pid_t pid, ProcessesStatus *child_list) {
    char path[64], buffer[512];
    FILE *file;
    pid_t ppid = -1;
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
            child_list->zombie[child_list->zombie_count++] = pid;
        } else {
            child_list->running[child_list->running_count++] = pid;
        }
    }
}

void ReadChild(pid_t parent_pid, ProcessesStatus *child_list) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    child_list->running_count = 0;
    child_list->zombie_count = 0;

    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;

        pid_t pid = atoi(entry->d_name);
        FindStatus(parent_pid, pid, child_list);
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    std::vector<char*> container_folders;

    ContinerDetail cont_configs[20];
    int num_containers = 0;
    std::unordered_map<int, pid_t> idx_pid_containers;
    parse_arguments(argc, argv, cont_configs, &num_containers);
    for (size_t i = 0; i < num_containers; i++)
    {
        cont_configs[i].core_number = (i % num_cores);
        int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
        if (IPC)
            flags |= CLONE_NEWIPC;
        pid_t child_pid = clone(Cont, stack_memory(), flags, (void *)&cont_configs[i]);
        printf("child process %d with hostname %s created.\n", child_pid, cont_configs[i].hostname);
        idx_pid_containers[child_pid] = i;
    }

    char command[256];
    while (1)
    {
        printf("commands: [list, restart {PID}, exit] :");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        
        if (strcmp(command, "list") == 0)
        {
            pid_t pid = getpid();
            ProcessesStatus child_list;
            ReadChild(pid, &child_list);
            
            printf("RUNNING containers:\n");
            for (size_t i = 0; i < child_list.running_count; i++)
            {
                int idx = idx_pid_containers[child_list.running[i]];
                printf("pid: %d\t\thostname: %s\n", child_list.running[i], cont_configs[idx].hostname);
            }
            printf("\nZOMBIE containers:\n");
            for (size_t i = 0; i < child_list.zombie_count; i++)
            {
                int idx = idx_pid_containers[child_list.zombie[i]];
                printf("pid: %d\t\thostname: %s\n", child_list.zombie[i], cont_configs[idx].hostname);
            }
            printf("\n");
        }
        else if((strcmp(command, "exit") == 0))
        {
            break;
        }
        else if (strncmp(command, "restart", 7) == 0)
        {
            pid_t pid = atoi(command + 8);
            ContinerDetail old_args = cont_configs[idx_pid_containers[pid]];
            printf("pid: %d\n", pid);
            if (kill(pid, SIGKILL) == 0)
            { }
            else {
                perror("unable to restart process");
            }
            num_containers++;
            cont_configs[num_containers - 1].container_id = time(nullptr);
            char *folder_name = (char*)malloc(256 * sizeof(char));
            snprintf(folder_name, 255, "folder_%ld", cont_configs[num_containers - 1].container_id);
            cont_configs[num_containers - 1].container_folder = folder_name;
            cont_configs[num_containers - 1].hostname = old_args.hostname;
            cont_configs[num_containers - 1].executable = old_args.executable;
            pid_t child_pid = clone(Cont, stack_memory(), CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, (void *)&cont_configs[num_containers - 1]);
            printf("child process %d with hostname %s created (replaced %d).\n", child_pid, cont_configs[num_containers - 1].hostname, pid);
            idx_pid_containers[child_pid] = num_containers - 1;
        }
    }
    for (size_t i = 0; i < num_containers; i++)
        pid_t pid = wait(nullptr);
}
