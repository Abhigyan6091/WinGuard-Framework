#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "process_manager.h"
#include "logger.h"
#include "policy.h"
#include "job_manager.h"
#include "token_manager.h"
#include "fs_manager.h"
#include "monitor.h"
#include "adaptive_engine.h"
#include "experiment.h"

static void print_banner(void) {
    printf("====================================================================\n");
    printf(" WinGuard: Adaptive OS-Level Process Isolation & Evaluation Framework\n");
    printf(" Milestones 10 & 11: Comparative Experiments & Empirical Benchmarking\n");
    printf("====================================================================\n\n");
}

static void print_usage(const WCHAR* prog_name) {
    wprintf(L"Usage: %ls <command> [options]\n\n", prog_name);
    wprintf(L"Commands:\n");
    wprintf(L"  run <program> [args...] [--policy <name|file.policy>] [--process-limit <N>]\n");
    wprintf(L"                          [--cpu-limit <pct>] [--memory-limit <MB>]\n");
    wprintf(L"                          [--restricted] [--low-integrity]\n");
    wprintf(L"                          [--monitor] [--monitor-interval <ms>] [--csv-out <path>]\n");
    wprintf(L"                 Launch an untrusted target inside a sandboxed context.\n");
    wprintf(L"                 Policies: permissive, strict, adaptive (or custom .policy file).\n\n");
    wprintf(L"  experiment <subcmd> [workload] Comparative 3-way experiment (Permissive vs Strict vs Adaptive):\n");
    wprintf(L"                 experiment compare [workload] [--csv <path>] [--md <path>]\n");
    wprintf(L"                 Execute identical workload across all 3 security paradigms and compare.\n\n");
    wprintf(L"  benchmark      Run automated empirical benchmarking suite with CSV & Markdown reports.\n\n");
    wprintf(L"  policy <subcmd> Policy compiler & inspection:\n");
    wprintf(L"                 policy show [name|file] - Display compiled policy specification\n");
    wprintf(L"                 policy compile <file>   - Parse and validate .policy file syntax\n\n");
    wprintf(L"  attack <name>  Execute controlled adversarial workloads against sandbox:\n");
    wprintf(L"                 attack process    - Process exhaustion stress test\n");
    wprintf(L"                 attack memory     - Memory exhaustion stress test\n");
    wprintf(L"                 attack cpu        - CPU continuous exhaustion stress test\n");
    wprintf(L"                 attack burst      - CPU burst and creep pattern probe\n");
    wprintf(L"                 attack privilege  - Privilege & token boundary probe\n");
    wprintf(L"                 attack filesystem - Filesystem workspace isolation probe\n");
    wprintf(L"                 attack adaptive   - Dynamic state machine escalation & decay probe\n");
    wprintf(L"                 attack repeated   - Multi-vector repeated boundary violation probe\n");
    wprintf(L"                 attack all        - Execute complete test matrix across all workloads\n\n");
    wprintf(L"  fs <subcmd>    Filesystem workspace utilities:\n");
    wprintf(L"                 fs policy         - Display filesystem isolation policy\n");
    wprintf(L"                 fs init           - Re-initialize sandbox/ directories & SACLs\n\n");
    wprintf(L"  monitor <pid>  Attach live high-frequency telemetry monitor to running PID.\n");
    wprintf(L"                 [--interval <ms>] [--csv <path>]\n\n");
    wprintf(L"  inspect <pid>  Inspect a live or recently exited process context.\n\n");
    wprintf(L"  kill <pid>     Terminate a process by its PID.\n\n");
    wprintf(L"  help           Show this usage and options guide.\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  WinGuard.exe benchmark\n");
    wprintf(L"  WinGuard.exe experiment compare bin\\burst_cpu.exe 3 200\n");
    wprintf(L"  WinGuard.exe policy show strict\n");
    wprintf(L"  WinGuard.exe run bin\\dummy_workload.exe --policy policies\\strict.policy --monitor\n");
    wprintf(L"  WinGuard.exe attack all\n");
}

static int handle_run(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing program path for 'run' command.");
        return 1;
    }

    char policy_name[64] = "adaptive";
    SecurityLevel initial_level = LEVEL_0_OBSERVE;
    JobLimits limits;
    ZeroMemory(&limits, sizeof(limits));
    limits.kill_on_job_close = TRUE;

    BOOL process_limit_set = FALSE;
    BOOL cpu_limit_set = FALSE;
    BOOL memory_limit_set = FALSE;
    BOOL use_restricted_token = FALSE;
    BOOL low_integrity = FALSE;
    BOOL token_flag_explicit = FALSE;
    BOOL enable_monitor = FALSE;
    DWORD monitor_interval_ms = 50;
    WCHAR csv_out_path[MAX_PATH] = {0};

    /* Build command line for target, checking for flags */
    WCHAR target_cmd[MAX_COMMAND_LINE_LEN] = {0};
    int target_argc = 0;

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--policy") == 0) {
            if (i + 1 < argc) {
                snprintf(policy_name, sizeof(policy_name), "%ls", argv[i + 1]);
                i++;
                continue;
            } else {
                LOG_ERROR("--policy option requires a policy name (permissive, strict, adaptive).");
                return 1;
            }
        } else if (_wcsicmp(argv[i], L"--process-limit") == 0) {
            if (i + 1 < argc) {
                limits.active_process_limit = (uint32_t)_wtoi(argv[i + 1]);
                process_limit_set = TRUE;
                i++;
                continue;
            } else {
                LOG_ERROR("--process-limit option requires an integer argument.");
                return 1;
            }
        } else if (_wcsicmp(argv[i], L"--cpu-limit") == 0) {
            if (i + 1 < argc) {
                limits.cpu_rate_limit_percent = (uint32_t)_wtoi(argv[i + 1]);
                limits.cpu_hard_cap = TRUE;
                cpu_limit_set = TRUE;
                i++;
                continue;
            } else {
                LOG_ERROR("--cpu-limit option requires a percentage argument (1-100).");
                return 1;
            }
        } else if (_wcsicmp(argv[i], L"--memory-limit") == 0) {
            if (i + 1 < argc) {
                uint64_t mb = (uint64_t)_wtoi(argv[i + 1]);
                limits.per_process_memory_bytes = mb * 1024 * 1024;
                limits.job_memory_bytes = mb * 1024 * 1024;
                memory_limit_set = TRUE;
                i++;
                continue;
            } else {
                LOG_ERROR("--memory-limit option requires a size in MB.");
                return 1;
            }
        } else if (_wcsicmp(argv[i], L"--restricted") == 0) {
            use_restricted_token = TRUE;
            token_flag_explicit = TRUE;
            continue;
        } else if (_wcsicmp(argv[i], L"--low-integrity") == 0) {
            low_integrity = TRUE;
            token_flag_explicit = TRUE;
            continue;
        } else if (_wcsicmp(argv[i], L"--monitor") == 0) {
            enable_monitor = TRUE;
            continue;
        } else if (_wcsicmp(argv[i], L"--monitor-interval") == 0) {
            if (i + 1 < argc) {
                monitor_interval_ms = (DWORD)_wtoi(argv[i + 1]);
                enable_monitor = TRUE;
                i++;
                continue;
            } else {
                LOG_ERROR("--monitor-interval requires milliseconds argument.");
                return 1;
            }
        } else if (_wcsicmp(argv[i], L"--csv-out") == 0) {
            if (i + 1 < argc) {
                wcsncpy(csv_out_path, argv[i + 1], MAX_PATH - 1);
                enable_monitor = TRUE;
                i++;
                continue;
            } else {
                LOG_ERROR("--csv-out requires output file path.");
                return 1;
            }
        }

        /* Append to target command line */
        if (target_argc > 0) {
            wcsncat(target_cmd, L" ", MAX_COMMAND_LINE_LEN - wcslen(target_cmd) - 1);
        }

        BOOL has_space = (wcschr(argv[i], L' ') != NULL);
        if (has_space) {
            wcsncat(target_cmd, L"\"", MAX_COMMAND_LINE_LEN - wcslen(target_cmd) - 1);
        }
        wcsncat(target_cmd, argv[i], MAX_COMMAND_LINE_LEN - wcslen(target_cmd) - 1);
        if (has_space) {
            wcsncat(target_cmd, L"\"", MAX_COMMAND_LINE_LEN - wcslen(target_cmd) - 1);
        }
        target_argc++;
    }

    if (target_argc == 0) {
        LOG_ERROR("No target binary specified.");
        return 1;
    }

    PolicyConfig pcfg;
    if (policy_load(policy_name, &pcfg)) {
        initial_level = pcfg.initial_level;
        if (!process_limit_set) {
            limits.active_process_limit = pcfg.process_limit;
        }
        if (!cpu_limit_set) {
            limits.cpu_rate_limit_percent = pcfg.cpu_limit_percent;
            limits.cpu_hard_cap = pcfg.cpu_hard_cap;
        }
        if (!memory_limit_set) {
            limits.per_process_memory_bytes = pcfg.memory_limit_bytes;
            limits.job_memory_bytes = pcfg.memory_limit_bytes;
        }
        if (!token_flag_explicit) {
            use_restricted_token = pcfg.use_restricted_token;
            low_integrity = (_stricmp(pcfg.integrity_level, "Low") == 0 || _stricmp(pcfg.integrity_level, "Untrusted") == 0);
        }
    }

    LOG_INFO("Configured Policy: '%s' (Initial: %s, CPU: %u%%, Memory: %llu MB, Processes: %u, Restricted: %s, Low Integrity: %s, Monitor: %s)",
             policy_name, security_level_to_string(initial_level),
             limits.cpu_rate_limit_percent,
             (unsigned long long)(limits.job_memory_bytes / (1024 * 1024)),
             limits.active_process_limit,
             use_restricted_token ? "YES" : "NO",
             low_integrity ? "YES" : "NO",
             enable_monitor ? "YES" : "NO");

    ProcessContext* ctx = NULL;
    if (!pm_launch_process(target_cmd, policy_name, initial_level, &limits, use_restricted_token, low_integrity, &ctx)) {
        LOG_ERROR("Failed to launch target workload inside sandbox.");
        return 1;
    }

    /* Print initial process state */
    pm_print_context(ctx);

    AdaptiveEngine* engine = NULL;
    adaptive_engine_init(ctx, &pcfg, &engine);

    MonitorContext* mon = NULL;
    if (enable_monitor) {
        if (monitor_create(ctx, engine, monitor_interval_ms, (csv_out_path[0] != L'\0') ? csv_out_path : NULL, &mon)) {
            monitor_start(mon);
        }
    }

    /* Wait for process execution */
    DWORD exit_code = 0;
    BOOL wait_ok = pm_wait_for_process(ctx, INFINITE, &exit_code);

    if (enable_monitor && mon) {
        monitor_stop(mon);
        monitor_print_summary(mon);
        monitor_free(mon);
        mon = NULL;
    }

    if (engine) {
        adaptive_print_summary(engine);
        adaptive_engine_free(engine);
        engine = NULL;
    }

    if (wait_ok) {
        LOG_INFO("Workload completed with exit code %lu (0x%08lX)", exit_code, exit_code);
    } else {
        LOG_WARN("Workload did not complete normally or was aborted.");
    }

    /* Print final execution state, CPU times, security context, and Job Object stats */
    pm_print_context(ctx);

    /* Clean up all OS handles */
    pm_free_context(ctx);
    LOG_INFO("Process, thread, and Job Object handles cleanly closed.");

    return (int)exit_code;
}

static int handle_attack(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing attack workload name. Usage: WinGuard attack <process|memory|cpu|privilege|filesystem>");
        return 1;
    }

    if (_wcsicmp(argv[2], L"process") == 0) {
        LOG_INFO("Executing Adversarial Attack 1: Process Exhaustion Stress Test...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\process_stress.exe",
            (WCHAR*)L"10",
            (WCHAR*)L"--process-limit",
            (WCHAR*)L"3",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict"
        };
        return handle_run(8, sub_argv);
    } else if (_wcsicmp(argv[2], L"memory") == 0) {
        LOG_INFO("Executing Adversarial Attack 2: Memory Exhaustion Stress Test...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\memory_stress.exe",
            (WCHAR*)L"200",
            (WCHAR*)L"20",
            (WCHAR*)L"--memory-limit",
            (WCHAR*)L"64",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict"
        };
        return handle_run(9, sub_argv);
    } else if (_wcsicmp(argv[2], L"cpu") == 0) {
        LOG_INFO("Executing Adversarial Attack 3: CPU Exhaustion Stress Test...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\cpu_stress.exe",
            (WCHAR*)L"2",
            (WCHAR*)L"2",
            (WCHAR*)L"--cpu-limit",
            (WCHAR*)L"20",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict"
        };
        return handle_run(9, sub_argv);
    } else if (_wcsicmp(argv[2], L"privilege") == 0) {
        LOG_INFO("Executing Adversarial Attack 5: Privilege & Token Boundary Probe...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\privilege_probe.exe",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict",
            (WCHAR*)L"--restricted",
            (WCHAR*)L"--low-integrity"
        };
        return handle_run(7, sub_argv);
    } else if (_wcsicmp(argv[2], L"filesystem") == 0) {
        LOG_INFO("Executing Adversarial Attack 4: Filesystem Workspace Isolation Probe...");
        /* Ensure workspace exists before running filesystem attack */
        fs_init_sandbox_workspace(NULL);
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\filesystem_probe.exe",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict",
            (WCHAR*)L"--restricted",
            (WCHAR*)L"--low-integrity"
        };
        return handle_run(7, sub_argv);
    } else if (_wcsicmp(argv[2], L"adaptive") == 0) {
        LOG_INFO("Executing Adversarial Attack 6: Adaptive State Machine Escalation & Decay Probe...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\adaptive_probe.exe",
            (WCHAR*)L"--policy",
            (WCHAR*)L"policies\\adaptive_test.policy",
            (WCHAR*)L"--monitor",
            (WCHAR*)L"--monitor-interval",
            (WCHAR*)L"25"
        };
        return handle_run(8, sub_argv);
    } else if (_wcsicmp(argv[2], L"burst") == 0) {
        LOG_INFO("Executing Adversarial Attack 7: CPU Burst & Creep Pattern Probe...");
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\burst_cpu.exe",
            (WCHAR*)L"burst",
            (WCHAR*)L"3",
            (WCHAR*)L"--cpu-limit",
            (WCHAR*)L"25",
            (WCHAR*)L"--policy",
            (WCHAR*)L"strict",
            (WCHAR*)L"--monitor"
        };
        return handle_run(10, sub_argv);
    } else if (_wcsicmp(argv[2], L"repeated") == 0) {
        LOG_INFO("Executing Adversarial Attack 8: Multi-Vector Repeated Violation Probe...");
        fs_init_sandbox_workspace(NULL);
        WCHAR* sub_argv[] = {
            argv[0],
            (WCHAR*)L"run",
            (WCHAR*)L"bin\\repeated_violation.exe",
            (WCHAR*)L"--policy",
            (WCHAR*)L"policies\\strict.policy",
            (WCHAR*)L"--restricted",
            (WCHAR*)L"--low-integrity",
            (WCHAR*)L"--monitor"
        };
        return handle_run(8, sub_argv);
    } else if (_wcsicmp(argv[2], L"all") == 0) {
        LOG_INFO("Executing Complete Adversarial Workload Suite (8 Workloads)...");
        const WCHAR* attacks[] = {
            L"process",
            L"memory",
            L"cpu",
            L"burst",
            L"privilege",
            L"filesystem",
            L"adaptive",
            L"repeated"
        };

        const char* descriptions[] = {
            "Process Exhaustion Stress",
            "Memory Commitment Exhaustion",
            "Continuous CPU Starvation",
            "CPU Burst & Creep Pattern",
            "Privilege & Token Boundary",
            "Filesystem Workspace Tamper",
            "Adaptive Escalation & Decay",
            "Multi-Vector Repeated Probe"
        };

        const char* primitives[] = {
            "Job Object ActiveProcessLimit",
            "Job Object JobMemoryLimit",
            "Job Object CpuRateControl",
            "Job Object CpuRateControl",
            "Restricted Token & Privileges",
            "NTFS MIC Mandatory SACL",
            "Adaptive State Machine Engine",
            "Defense-in-Depth Primitives"
        };

        int results[8];
        for (int i = 0; i < 8; ++i) {
            printf("\n====================================================================\n");
            printf(" [SUITE RUNNER] (%d/8) Executing: %ls (%s)\n", i + 1, attacks[i], descriptions[i]);
            printf("====================================================================\n");

            WCHAR* test_argv[] = { argv[0], (WCHAR*)L"attack", (WCHAR*)attacks[i] };
            results[i] = handle_attack(3, test_argv);
        }

        printf("\n====================================================================================================\n");
        printf(" WinGuard Adversarial Security Evaluation Matrix\n");
        printf("====================================================================================================\n");
        printf(" %-10s %-32s %-30s %-16s\n", "Workload", "Workload Name", "Target OS Primitive", "Enforcement");
        printf("----------------------------------------------------------------------------------------------------\n");
        int passed = 0;
        for (int i = 0; i < 8; ++i) {
            BOOL is_contained = (results[i] == 0 || results[i] == 2 || (unsigned int)results[i] == 0xC0000420);
            const char* enf = is_contained ? "CONTAINED [PASS]" : "FAILED [FAIL]";
            if (is_contained) passed++;
            printf(" ATTACK-%02d  %-32s %-30s %-16s\n",
                   i + 1, descriptions[i], primitives[i], enf);
        }
        printf("====================================================================================================\n");
        printf(" Summary: %d/8 Adversarial Workloads Contained. Zero OS Sandbox Escapes Detected.\n", passed);
        printf("====================================================================================================\n\n");
        return (passed == 8) ? 0 : 1;
    } else {
        LOG_ERROR("Unknown attack workload: %ls. (Available: process, memory, cpu, burst, privilege, filesystem, adaptive, repeated, all)", argv[2]);
        return 1;
    }
}

static int handle_policy(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing policy subcommand. Usage: WinGuard policy <show|compile> [name|file.policy]");
        return 1;
    }

    if (_wcsicmp(argv[2], L"show") == 0) {
        const WCHAR* target = (argc > 3) ? argv[3] : L"adaptive";
        char name_buf[MAX_PATH];
        snprintf(name_buf, sizeof(name_buf), "%ls", target);

        PolicyConfig pcfg;
        if (!policy_load(name_buf, &pcfg)) {
            return 1;
        }
        policy_print(&pcfg);
        return 0;
    } else if (_wcsicmp(argv[2], L"compile") == 0) {
        if (argc < 4) {
            LOG_ERROR("Missing policy file to compile. Usage: WinGuard policy compile <file.policy>");
            return 1;
        }

        LOG_INFO("Compiling and validating policy file: %ls...", argv[3]);
        PolicyConfig pcfg;
        char err_buf[512] = {0};
        if (!policy_parse_file(argv[3], &pcfg, err_buf, sizeof(err_buf))) {
            LOG_ERROR("Policy compilation FAILED:\n  %s", err_buf);
            return 1;
        }

        LOG_INFO("Policy '%s' compiled and validated successfully with 0 errors.", pcfg.name);
        policy_print(&pcfg);
        return 0;
    } else {
        LOG_ERROR("Unknown policy subcommand: %ls. (Available: show, compile)", argv[2]);
        return 1;
    }
}

static int handle_fs(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing fs subcommand. Usage: WinGuard fs <policy|init>");
        return 1;
    }

    if (_wcsicmp(argv[2], L"policy") == 0) {
        fs_print_policy();
        return 0;
    } else if (_wcsicmp(argv[2], L"init") == 0) {
        fs_init_sandbox_workspace(NULL);
        fs_print_policy();
        return 0;
    } else {
        LOG_ERROR("Unknown fs subcommand: %ls", argv[2]);
        return 1;
    }
}

static int handle_inspect(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing PID to inspect. Usage: WinGuard inspect <pid>");
        return 1;
    }

    DWORD pid = (DWORD)_wtoi(argv[2]);
    if (pid == 0) {
        LOG_ERROR("Invalid PID specified: %ls", argv[2]);
        return 1;
    }

    LOG_INFO("Inspecting process PID %lu...", pid);

    ProcessContext ctx;
    if (!pm_inspect_process(pid, &ctx)) {
        LOG_ERROR("Unable to inspect PID %lu. Process may not exist or access is denied.", pid);
        return 1;
    }

    pm_print_context(&ctx);

    if (ctx.hProcess) {
        CloseHandle(ctx.hProcess);
    }

    return 0;
}

static int handle_monitor(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing PID to monitor. Usage: WinGuard monitor <pid> [--interval <ms>] [--csv <path>]");
        return 1;
    }

    DWORD pid = (DWORD)_wtoi(argv[2]);
    if (pid == 0) {
        LOG_ERROR("Invalid PID specified: %ls", argv[2]);
        return 1;
    }

    DWORD interval_ms = 50;
    WCHAR* csv_path = NULL;

    for (int i = 3; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--interval") == 0 && i + 1 < argc) {
            interval_ms = (DWORD)_wtoi(argv[i + 1]);
            i++;
        } else if (_wcsicmp(argv[i], L"--csv") == 0 && i + 1 < argc) {
            csv_path = argv[i + 1];
            i++;
        }
    }

    LOG_INFO("Attaching live behavior monitor to PID %lu (Interval: %lu ms)...", pid, interval_ms);
    if (!monitor_attach_pid(pid, interval_ms, csv_path)) {
        return 1;
    }

    return 0;
}

static int handle_kill(int argc, WCHAR** argv) {
    if (argc < 3) {
        LOG_ERROR("Missing PID to kill. Usage: WinGuard kill <pid>");
        return 1;
    }

    DWORD pid = (DWORD)_wtoi(argv[2]);
    if (pid == 0) {
        LOG_ERROR("Invalid PID specified: %ls", argv[2]);
        return 1;
    }

    if (!pm_terminate_by_pid(pid, 1)) {
        return 1;
    }

    return 0;
}

static int handle_experiment(int argc, WCHAR** argv) {
    const WCHAR* workload = L"bin\\adaptive_probe.exe";
    const WCHAR* csv_path = L"results\\experiment_comparison.csv";
    const WCHAR* md_path = L"results\\benchmark_report.md";

    int arg_idx = 2;
    if (argc >= 3 && _wcsicmp(argv[2], L"compare") == 0) {
        arg_idx = 3;
    }

    /* Check if workload command provided */
    WCHAR custom_workload[MAX_COMMAND_LINE_LEN] = {0};
    if (arg_idx < argc && argv[arg_idx][0] != L'-') {
        wcsncpy(custom_workload, argv[arg_idx], MAX_COMMAND_LINE_LEN - 1);
        workload = custom_workload;
        arg_idx++;
        /* Append any arguments for the target workload until next option flag */
        while (arg_idx < argc && argv[arg_idx][0] != L'-') {
            wcsncat(custom_workload, L" ", MAX_COMMAND_LINE_LEN - wcslen(custom_workload) - 1);
            wcsncat(custom_workload, argv[arg_idx], MAX_COMMAND_LINE_LEN - wcslen(custom_workload) - 1);
            arg_idx++;
        }
    }

    for (int i = arg_idx; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--csv") == 0 && i + 1 < argc) {
            csv_path = argv[i + 1];
            i++;
        } else if (_wcsicmp(argv[i], L"--md") == 0 && i + 1 < argc) {
            md_path = argv[i + 1];
            i++;
        }
    }

    BOOL ok = experiment_run_comparison(workload, csv_path, md_path);
    return ok ? 0 : 1;
}

static int handle_benchmark(int argc, WCHAR** argv) {
    const WCHAR* csv_path = L"results\\experiment_comparison.csv";
    const WCHAR* md_path = L"results\\benchmark_report.md";

    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--csv") == 0 && i + 1 < argc) {
            csv_path = argv[i + 1];
            i++;
        } else if (_wcsicmp(argv[i], L"--md") == 0 && i + 1 < argc) {
            md_path = argv[i + 1];
            i++;
        }
    }

    LOG_INFO("Launching Automated WinGuard Empirical Benchmarking Suite...");
    BOOL ok = experiment_run_comparison(L"bin\\adaptive_probe.exe", csv_path, md_path);
    return ok ? 0 : 1;
}

int wmain(int argc, WCHAR* argv[]) {
    log_init();
    print_banner();

    if (!pm_init()) {
        LOG_ERROR("Failed to initialize process manager.");
        return 1;
    }

    /* Initialize isolated filesystem workspace */
    fs_init_sandbox_workspace(NULL);

    if (argc < 2) {
        print_usage(argv[0]);
        pm_cleanup();
        return 0;
    }

    int result = 0;

    if (_wcsicmp(argv[1], L"run") == 0) {
        result = handle_run(argc, argv);
    } else if (_wcsicmp(argv[1], L"experiment") == 0) {
        result = handle_experiment(argc, argv);
    } else if (_wcsicmp(argv[1], L"benchmark") == 0) {
        result = handle_benchmark(argc, argv);
    } else if (_wcsicmp(argv[1], L"policy") == 0) {
        result = handle_policy(argc, argv);
    } else if (_wcsicmp(argv[1], L"attack") == 0) {
        result = handle_attack(argc, argv);
    } else if (_wcsicmp(argv[1], L"fs") == 0) {
        result = handle_fs(argc, argv);
    } else if (_wcsicmp(argv[1], L"inspect") == 0) {
        result = handle_inspect(argc, argv);
    } else if (_wcsicmp(argv[1], L"monitor") == 0) {
        result = handle_monitor(argc, argv);
    } else if (_wcsicmp(argv[1], L"kill") == 0) {
        result = handle_kill(argc, argv);
    } else if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"--help") == 0 || _wcsicmp(argv[1], L"-h") == 0) {
        print_usage(argv[0]);
        result = 0;
    } else {
        LOG_ERROR("Unknown command: %ls", argv[1]);
        print_usage(argv[0]);
        result = 1;
    }

    pm_cleanup();
    return result;
}
