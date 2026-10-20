#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif
#include "cipherdns/core.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

static atomic_flag hook_busy = ATOMIC_FLAG_INIT;
#ifdef _WIN32
static volatile LONG stop_flag;
static HANDLE lock_handle = INVALID_HANDLE_VALUE;
static BOOL WINAPI control_handler(DWORD code) {
    if (code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT || code == CTRL_CLOSE_EVENT ||
        code == CTRL_SHUTDOWN_EVENT) {
        InterlockedExchange(&stop_flag, 1);
        return TRUE;
    }
    return FALSE;
}
int cdns_platform_init(void) {
    WSADATA data;
    InterlockedExchange(&stop_flag, 0);
    if (WSAStartup(MAKEWORD(2, 2), &data))
        return -1;
    if (!SetConsoleCtrlHandler(control_handler, TRUE)) {
        WSACleanup();
        return -1;
    }
    return 0;
}
void cdns_platform_cleanup(void) {
    cdns_unlock();
    SetConsoleCtrlHandler(control_handler, FALSE);
    WSACleanup();
}
uint64_t cdns_mono_ms(void) {
    return (uint64_t)GetTickCount64();
}
int cdns_stopping(void) {
    return InterlockedCompareExchange(&stop_flag, 0, 0) != 0;
}
void cdns_sleep_ms(unsigned ms) {
    uint64_t end = cdns_mono_ms() + ms;
    while (!cdns_stopping() && cdns_mono_ms() < end) {
        uint64_t left = end - cdns_mono_ms();
        Sleep((DWORD)(left > 50 ? 50 : left));
    }
}

static TOKEN_USER *current_user(void) {
    HANDLE token;
    DWORD n = 0;
    TOKEN_USER *user;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &n);
    user = malloc(n);
    if (!user || !GetTokenInformation(token, TokenUser, user, n, &n)) {
        free(user);
        user = NULL;
    }
    CloseHandle(token);
    return user;
}
static int private_handle(HANDLE file) {
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    PACL acl = NULL;
    TOKEN_USER *user = current_user();
    BYTE system_sid[SECURITY_MAX_SID_SIZE], admin_sid[SECURITY_MAX_SID_SIZE];
    DWORD system_n = sizeof system_sid, admin_n = sizeof admin_sid;
    BY_HANDLE_FILE_INFORMATION info;
    int valid = 0;
    if (!user || !GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        goto done;
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &system_n) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &admin_n))
        goto done;
    if (GetSecurityInfo(file, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &acl,
                        NULL, &sd) != ERROR_SUCCESS ||
        !acl || !EqualSid(owner, user->User.Sid))
        goto done;
    {
        DWORD i;
        for (i = 0; i < acl->AceCount; ++i) {
            PVOID item;
            ACE_HEADER *header;
            if (!GetAce(acl, i, &item))
                goto done;
            header = item;
            if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE *ace = item;
                PSID sid = (PSID)&ace->SidStart;
                if (ace->Mask && !EqualSid(sid, user->User.Sid) && !EqualSid(sid, system_sid) &&
                    !EqualSid(sid, admin_sid))
                    goto done;
            } else if (header->AceType != ACCESS_DENIED_ACE_TYPE &&
                       header->AceType != SYSTEM_AUDIT_ACE_TYPE)
                goto done;
        }
    }
    valid = 1;
done:
    if (sd)
        LocalFree(sd);
    free(user);
    return valid ? 0 : -1;
}
int cdns_private_file(const char *path) {
    HANDLE file;
    int rc;
    if (!path)
        return -1;
    file = CreateFileA(path, READ_CONTROL | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;
    rc = private_handle(file);
    CloseHandle(file);
    return rc;
}
static HANDLE private_create(const char *path, DWORD creation, DWORD share) {
    TOKEN_USER *user = current_user();
    EXPLICIT_ACCESSA entry;
    PACL acl = NULL;
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_ATTRIBUTES attributes;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (!user)
        return file;
    memset(&entry, 0, sizeof entry);
    entry.grfAccessPermissions = GENERIC_ALL;
    entry.grfAccessMode = SET_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = (LPSTR)user->User.Sid;
    if (SetEntriesInAclA(1, &entry, NULL, &acl) != ERROR_SUCCESS ||
        !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&descriptor, user->User.Sid, FALSE) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        goto done;
    attributes.nLength = sizeof attributes;
    attributes.lpSecurityDescriptor = &descriptor;
    attributes.bInheritHandle = FALSE;
    file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, share, &attributes, creation,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
done:
    if (acl)
        LocalFree(acl);
    free(user);
    return file;
}
int cdns_private_create(const char *path, const void *data, size_t n) {
    HANDLE file;
    size_t used = 0;
    int rc = -1;
    if (!path || !data)
        return -1;
    file = private_create(path, CREATE_NEW, 0);
    if (file == INVALID_HANDLE_VALUE)
        return -1;
    while (used < n) {
        DWORD written = 0, chunk = (DWORD)((n - used) > 65536 ? 65536 : n - used);
        if (!WriteFile(file, (const unsigned char *)data + used, chunk, &written, NULL) || !written)
            goto done;
        used += written;
    }
    if (FlushFileBuffers(file))
        rc = 0;
done:
    if (!CloseHandle(file))
        rc = -1;
    if (rc)
        DeleteFileA(path);
    return rc;
}
int cdns_atomic_write(const char *path, const void *data, size_t n) {
    unsigned char random[8];
    char temporary[CDNS_PATH_MAX + 40];
    HANDLE file;
    size_t used = 0;
    int rc = -1;
    if (!path || !data || strlen(path) >= CDNS_PATH_MAX || cdns_random(random, sizeof random))
        return -1;
    if (snprintf(temporary, sizeof temporary, "%s.tmp.%02x%02x%02x%02x%02x%02x%02x%02x", path,
                 random[0], random[1], random[2], random[3], random[4], random[5], random[6],
                 random[7]) < 0)
        return -1;
    file = private_create(temporary, CREATE_NEW, 0);
    if (file == INVALID_HANDLE_VALUE)
        return -1;
    while (used < n) {
        DWORD written = 0, chunk = (DWORD)((n - used) > 65536 ? 65536 : n - used);
        if (!WriteFile(file, (const unsigned char *)data + used, chunk, &written, NULL) || !written)
            goto done;
        used += written;
    }
    if (!FlushFileBuffers(file))
        goto done;
    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto done;
    }
    file = INVALID_HANDLE_VALUE;
    if (MoveFileExA(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        rc = 0;
done:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (rc)
        DeleteFileA(temporary);
    return rc;
}
int cdns_lock(const char *path) {
    if (lock_handle != INVALID_HANDLE_VALUE)
        return -1;
    lock_handle = private_create(path, OPEN_ALWAYS, 0);
    if (lock_handle == INVALID_HANDLE_VALUE)
        return -1;
    if (private_handle(lock_handle)) {
        CloseHandle(lock_handle);
        lock_handle = INVALID_HANDLE_VALUE;
        return -1;
    }
    return 0;
}
void cdns_unlock(void) {
    if (lock_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(lock_handle);
        lock_handle = INVALID_HANDLE_VALUE;
    }
}

/* Quote one argument using the Microsoft C runtime argument convention. */
static int quote_arg(char *out, size_t cap, size_t *used, const char *arg) {
    size_t slash = 0;
#define ADD_CHAR(ch)                                                                               \
    do {                                                                                           \
        if (*used + 1 >= cap)                                                                      \
            return -1;                                                                             \
        out[(*used)++] = (ch);                                                                     \
    } while (0)
    ADD_CHAR('"');
    for (;;) {
        char ch = *arg++;
        if (ch == '\\') {
            ++slash;
            continue;
        }
        if (ch == '"' || !ch) {
            size_t i;
            for (i = 0; i < slash * 2; ++i)
                ADD_CHAR('\\');
            if (ch == '"')
                ADD_CHAR('\\');
        } else {
            while (slash) {
                ADD_CHAR('\\');
                --slash;
            }
        }
        slash = 0;
        if (!ch)
            break;
        ADD_CHAR(ch);
    }
    ADD_CHAR('"');
    out[*used] = 0;
#undef ADD_CHAR
    return 0;
}
static int process_run(const char *application, char *command, unsigned timeout_s, char *out,
                       size_t cap) {
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    STARTUPINFOA start;
    PROCESS_INFORMATION process;
    HANDLE read_pipe = NULL, write_pipe = NULL, null_file = INVALID_HANDLE_VALUE, job = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    uint64_t deadline;
    size_t used = 0;
    int rc = -1, started = 0, overflow = 0;
    memset(&start, 0, sizeof start);
    start.cb = sizeof start;
    memset(&process, 0, sizeof process);
    if (!timeout_s || (out && !cap))
        return -1;
    if (out) {
        out[0] = 0;
        if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0) ||
            !SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0))
            goto done;
    }
    null_file = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (null_file == INVALID_HANDLE_VALUE)
        goto done;
    start.dwFlags = STARTF_USESTDHANDLES;
    start.hStdInput = null_file;
    start.hStdOutput = out ? write_pipe : null_file;
    start.hStdError = null_file;
    job = CreateJobObjectA(NULL, NULL);
    memset(&limits, 0, sizeof limits);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job ||
        !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits))
        goto done;
    if (!CreateProcessA(application, command, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &start, &process))
        goto done;
    started = 1;
    if (!AssignProcessToJobObject(job, process.hProcess))
        goto done;
    if (ResumeThread(process.hThread) == (DWORD)-1)
        goto done;
    if (write_pipe) {
        CloseHandle(write_pipe);
        write_pipe = NULL;
    }
    deadline = cdns_mono_ms() + (uint64_t)timeout_s * 1000;
    for (;;) {
        DWORD result;
        if (out) {
            DWORD available = 0;
            if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) {
                if (GetLastError() != ERROR_BROKEN_PIPE)
                    goto done;
                available = 0;
            }
            while (available) {
                char buffer[512];
                DWORD got, chunk = available > sizeof buffer ? sizeof buffer : available;
                if (!ReadFile(read_pipe, buffer, chunk, &got, NULL) || !got)
                    goto done;
                if ((size_t)got > cap - 1 - used) {
                    overflow = 1;
                    break;
                }
                memcpy(out + used, buffer, got);
                used += got;
                out[used] = 0;
                available -= got;
            }
            if (overflow)
                goto done;
        }
        result = WaitForSingleObject(process.hProcess, 20);
        if (result == WAIT_OBJECT_0) {
            DWORD code;
            /* Drain once more: the final process write can race the previous peek. */
            if (out) {
                DWORD available = 0;
                if (PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL) && available)
                    continue;
            }
            if (GetExitCodeProcess(process.hProcess, &code) && !code)
                rc = 0;
            break;
        }
        if (result == WAIT_FAILED || cdns_stopping() || cdns_mono_ms() >= deadline)
            break;
    }
done:
    if (started) {
        if (rc) {
            TerminateJobObject(job, 1);
            TerminateProcess(process.hProcess, 1);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if (job)
        CloseHandle(job);
    if (read_pipe)
        CloseHandle(read_pipe);
    if (write_pipe)
        CloseHandle(write_pipe);
    if (null_file != INVALID_HANDLE_VALUE)
        CloseHandle(null_file);
    return rc;
}
int cdns_capture(const char *command, unsigned timeout_s, char *out, size_t cap) {
    char shell[CDNS_PATH_MAX], line[CDNS_PATH_MAX * 3];
    static const char options[] = " /D /S /C \"";
    size_t used = 0;
    UINT n = GetSystemDirectoryA(shell, sizeof shell);
    if (!command || !out || !n || n + 9 >= sizeof shell)
        return -1;
    memcpy(shell + n, "\\cmd.exe", 9);
    if (quote_arg(line, sizeof line, &used, shell) || used + strlen(command) + 12 >= sizeof line)
        return -1;
    memcpy(line + used, options, sizeof options - 1);
    used += sizeof options - 1;
    memcpy(line + used, command, strlen(command));
    used += strlen(command);
    line[used++] = '"';
    line[used] = 0;
    return process_run(shell, line, timeout_s, out, cap);
}
int cdns_hook(const char *path, const char *json_path, unsigned timeout_s) {
    char application[CDNS_PATH_MAX], line[CDNS_PATH_MAX * 5];
    size_t used = 0, n;
    int rc = -1;
    if (!path || !json_path || strlen(path) >= sizeof application ||
        !((path[0] && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
          (path[0] == '\\' && path[1] == '\\')) ||
        !((json_path[0] && json_path[1] == ':' && (json_path[2] == '\\' || json_path[2] == '/')) ||
          (json_path[0] == '\\' && json_path[1] == '\\')))
        return -1;
    if (atomic_flag_test_and_set(&hook_busy))
        return -1;
    n = strlen(path);
    if (n > 4 && !_stricmp(path + n - 4, ".ps1")) {
        UINT count = GetSystemDirectoryA(application, sizeof application);
        const char *suffix = "\\WindowsPowerShell\\v1.0\\powershell.exe";
        static const char options[] = " -NoProfile -NonInteractive -File ";
        if (!count || count + strlen(suffix) >= sizeof application)
            goto done;
        memcpy(application + count, suffix, strlen(suffix) + 1);
        if (quote_arg(line, sizeof line, &used, application))
            goto done;
        memcpy(line + used, options, sizeof options - 1);
        used += sizeof options - 1;
        if (quote_arg(line, sizeof line, &used, path))
            goto done;
    } else {
        if (n < 4 || (_stricmp(path + n - 4, ".exe") && _stricmp(path + n - 4, ".com")))
            goto done;
        memcpy(application, path, n + 1);
        if (quote_arg(line, sizeof line, &used, path))
            goto done;
    }
    line[used++] = ' ';
    if (quote_arg(line, sizeof line, &used, json_path))
        goto done;
    rc = process_run(application, line, timeout_s, NULL, 0);
done:
    atomic_flag_clear(&hook_busy);
    return rc;
}
#else
static volatile sig_atomic_t stop_flag;
static int lock_fd = -1;
static void stop_handler(int signal_number) {
    (void)signal_number;
    stop_flag = 1;
}
int cdns_platform_init(void) {
    struct sigaction action;
    stop_flag = 0;
    memset(&action, 0, sizeof action);
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL))
        return -1;
    action.sa_handler = SIG_IGN;
    return sigaction(SIGPIPE, &action, NULL);
}
void cdns_platform_cleanup(void) {
    cdns_unlock();
}
uint64_t cdns_mono_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value))
        return 0;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
int cdns_stopping(void) {
    return stop_flag != 0;
}
void cdns_sleep_ms(unsigned ms) {
    struct timespec interval;
    interval.tv_sec = ms / 1000;
    interval.tv_nsec = (long)(ms % 1000) * 1000000;
    while (!cdns_stopping() && nanosleep(&interval, &interval) && errno == EINTR) {
    }
}
int cdns_private_file(const char *path) {
    struct stat st;
    if (!path || lstat(path, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077))
        return -1;
    return 0;
}
int cdns_private_create(const char *path, const void *data, size_t n) {
    int flags = O_WRONLY | O_CREAT | O_EXCL, fd, rc = -1;
    size_t used = 0;
    if (!path || !data)
        return -1;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(path, flags, 0600);
    if (fd < 0)
        return -1;
    while (used < n) {
        ssize_t bytes = write(fd, (const unsigned char *)data + used, n - used);
        if (bytes < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (!bytes)
            goto done;
        used += (size_t)bytes;
    }
    if (!fsync(fd))
        rc = 0;
done:
    if (close(fd))
        rc = -1;
    if (rc)
        unlink(path);
    return rc;
}
int cdns_atomic_write(const char *path, const void *data, size_t n) {
    unsigned char random[8];
    char temporary[CDNS_PATH_MAX + 40], directory[CDNS_PATH_MAX];
    size_t used = 0;
    int fd = -1, rc = -1, flags = O_WRONLY | O_CREAT | O_EXCL;
    if (!path || !data || !*path || strlen(path) >= CDNS_PATH_MAX ||
        cdns_random(random, sizeof random))
        return -1;
    if (snprintf(temporary, sizeof temporary, "%s.tmp.%02x%02x%02x%02x%02x%02x%02x%02x", path,
                 random[0], random[1], random[2], random[3], random[4], random[5], random[6],
                 random[7]) < 0)
        return -1;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(temporary, flags, 0600);
    if (fd < 0)
        return -1;
    if (fchmod(fd, 0600))
        goto done;
    while (used < n) {
        ssize_t bytes = write(fd, (const unsigned char *)data + used, n - used);
        if (bytes < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (!bytes)
            goto done;
        used += (size_t)bytes;
    }
    if (fsync(fd))
        goto done;
    if (close(fd)) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (rename(temporary, path))
        goto done;
    memcpy(directory, path, strlen(path) + 1);
    {
        char *slash = strrchr(directory, '/');
        int parent;
        if (!slash)
            memcpy(directory, ".", 2);
        else if (slash == directory)
            slash[1] = 0;
        else
            *slash = 0;
        parent = open(directory, O_RDONLY);
        if (parent < 0)
            goto done;
        if (fsync(parent) && errno != EINVAL && errno != EROFS) {
            close(parent);
            goto done;
        }
        if (close(parent))
            goto done;
    }
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (rc)
        unlink(temporary);
    return rc;
}
int cdns_lock(const char *path) {
    struct stat st;
    int fd, flags = O_RDWR | O_CREAT;
    if (!path || lock_fd >= 0)
        return -1;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(path, flags, 0600);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || fchmod(fd, 0600) ||
        flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd);
        return -1;
    }
    lock_fd = fd;
    return 0;
}
void cdns_unlock(void) {
    if (lock_fd >= 0) {
        close(lock_fd);
        lock_fd = -1;
    }
}

static int process_run(const char *command, const char *json_path, unsigned timeout_s, char *out,
                       size_t cap) {
    int fds[2] = {-1, -1}, status = 0, child_done = 0, eof = !out, rc = -1;
    size_t used = 0;
    pid_t pid;
    uint64_t deadline;
    if (!command || !timeout_s || (out && !cap))
        return -1;
    if (out) {
        out[0] = 0;
        if (pipe(fds))
            return -1;
    }
    pid = fork();
    if (pid < 0) {
        if (out) {
            close(fds[0]);
            close(fds[1]);
        }
        return -1;
    }
    if (!pid) {
        struct sigaction action;
        int null_fd;
        setpgid(0, 0);
        memset(&action, 0, sizeof action);
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGPIPE, &action, NULL);
        null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            if (dup2(null_fd, STDIN_FILENO) < 0)
                _exit(126);
            if (null_fd > 2)
                close(null_fd);
        }
        if (out) {
            close(fds[0]);
            if (dup2(fds[1], STDOUT_FILENO) < 0)
                _exit(126);
            if (fds[1] > 2)
                close(fds[1]);
        }
        if (json_path) {
            char *const argv[] = {(char *)command, (char *)json_path, NULL};
            execv(command, argv);
        } else
            execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    if (out) {
        close(fds[1]);
        fds[1] = -1;
        if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0)
            goto done;
    }
    deadline = cdns_mono_ms() + (uint64_t)timeout_s * 1000;
    for (;;) {
        pid_t waited;
        if (out && !eof) {
            for (;;) {
                char buffer[512];
                ssize_t bytes = read(fds[0], buffer, sizeof buffer);
                if (bytes < 0) {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    goto done;
                }
                if (!bytes) {
                    eof = 1;
                    break;
                }
                if ((size_t)bytes > cap - 1 - used)
                    goto done;
                memcpy(out + used, buffer, (size_t)bytes);
                used += (size_t)bytes;
                out[used] = 0;
            }
        }
        if (!child_done) {
            waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid)
                child_done = 1;
            else if (waited < 0 && errno != EINTR)
                goto done;
        }
        if (child_done && eof) {
            if (WIFEXITED(status) && !WEXITSTATUS(status))
                rc = 0;
            break;
        }
        if (cdns_stopping() || cdns_mono_ms() >= deadline)
            break;
        if (out && !eof) {
            struct pollfd pfd = {fds[0], POLLIN, 0};
            if (poll(&pfd, 1, 20) < 0 && errno != EINTR)
                break;
        } else {
            struct timespec pause = {0, 20000000};
            nanosleep(&pause, NULL);
        }
    }
done:
    /* A Hook must finish all of its work before returning. Descendants cannot
     * outlive even a successful leader and overlap a later Hook invocation. */
    kill(-pid, SIGKILL);
    if (rc) {
        kill(pid, SIGKILL);
    }
    if (out)
        close(fds[0]);
    if (!child_done)
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
    return rc;
}
int cdns_capture(const char *command, unsigned timeout_s, char *out, size_t cap) {
    if (!out)
        return -1;
    return process_run(command, NULL, timeout_s, out, cap);
}
int cdns_hook(const char *path, const char *json_path, unsigned timeout_s) {
    int rc;
    if (!path || path[0] != '/' || !json_path || json_path[0] != '/')
        return -1;
    if (atomic_flag_test_and_set(&hook_busy))
        return -1;
    rc = process_run(path, json_path, timeout_s, NULL, 0);
    atomic_flag_clear(&hook_busy);
    return rc;
}
#endif

int cdns_tcp_probe(const char *ip, unsigned port, unsigned timeout_s) {
    struct addrinfo hints, *addresses = NULL;
    char service[8];
    int rc = -1;
    uint64_t deadline;
#ifdef _WIN32
    SOCKET socket_fd = INVALID_SOCKET;
#else
    int socket_fd = -1;
#endif
    if (!ip || !*ip || !port || port > 65535 || !timeout_s)
        return -1;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    snprintf(service, sizeof service, "%u", port);
    if (getaddrinfo(ip, service, &hints, &addresses))
        return -1;
    socket_fd = socket(addresses->ai_family, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
    if (socket_fd == INVALID_SOCKET)
        goto done;
    {
        u_long nonblocking = 1;
        if (ioctlsocket(socket_fd, FIONBIO, &nonblocking))
            goto done;
    }
#else
    if (socket_fd < 0)
        goto done;
    if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) < 0)
        goto done;
#endif
    if (!connect(socket_fd, addresses->ai_addr, (int)addresses->ai_addrlen)) {
        rc = 0;
        goto done;
    }
#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAEINPROGRESS)
        goto done;
#else
    if (errno != EINPROGRESS && errno != EINTR)
        goto done;
#endif
    deadline = cdns_mono_ms() + (uint64_t)timeout_s * 1000;
    while (!cdns_stopping() && cdns_mono_ms() < deadline) {
        int ready, error = 0;
#ifdef _WIN32
        fd_set writable, exceptional;
        struct timeval interval = {0, 50000};
        int len = sizeof error;
        FD_ZERO(&writable);
        FD_ZERO(&exceptional);
        FD_SET(socket_fd, &writable);
        FD_SET(socket_fd, &exceptional);
        ready = select(0, NULL, &writable, &exceptional, &interval);
        if (ready > 0 && !getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) &&
            !error)
            rc = 0;
        if (ready == SOCKET_ERROR)
            break;
#else
        struct pollfd pfd = {socket_fd, POLLOUT, 0};
        socklen_t len = sizeof error;
        ready = poll(&pfd, 1, 50);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ready > 0 && !getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &len) && !error)
            rc = 0;
#endif
        if (ready > 0)
            break;
    }
done:
    freeaddrinfo(addresses);
#ifdef _WIN32
    if (socket_fd != INVALID_SOCKET)
        closesocket(socket_fd);
#else
    if (socket_fd >= 0)
        close(socket_fd);
#endif
    return rc;
}
