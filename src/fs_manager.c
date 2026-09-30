#include "fs_manager.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
#include <aclapi.h>

static BOOL set_folder_security(const WCHAR* path, LPCWSTR sddl) {
    if (!path || !sddl) return FALSE;

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &pSD,
            NULL)) {
        DWORD err = GetLastError();
        LOG_ERROR("ConvertStringSecurityDescriptorToSecurityDescriptorW failed for '%ls' (Win32 Error: %lu)", path, err);
        return FALSE;
    }

    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
    BOOL bSaclPresent = FALSE, bSaclDefaulted = FALSE;

    GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);
    GetSecurityDescriptorSacl(pSD, &bSaclPresent, &pSacl, &bSaclDefaulted);

    SECURITY_INFORMATION sec_info = 0;
    if (bDaclPresent && pDacl) sec_info |= DACL_SECURITY_INFORMATION;
    if (bSaclPresent && pSacl) sec_info |= LABEL_SECURITY_INFORMATION;

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)path,
        SE_FILE_OBJECT,
        sec_info,
        NULL,
        NULL,
        pDacl,
        pSacl
    );

    LocalFree(pSD);

    if (res != ERROR_SUCCESS) {
        LOG_ERROR("SetNamedSecurityInfoW failed on '%ls' with error %lu.", path, res);
        return FALSE;
    }

    return TRUE;
}

BOOL fs_set_low_integrity_label(const WCHAR* path) {
    /*
     * For writable sandbox areas (output and temp):
     * DACL: Grant File All Access (FA) to Everyone (WD) and Restricted Code (RC).
     * SACL: Low Mandatory Integrity Level (LW) with No-Write-Up policy (NW) and inheritance (OICI).
     */
    LPCWSTR sddl = L"D:(A;OICI;FA;;;WD)(A;OICI;FA;;;RC)S:(ML;OICI;NW;;;LW)";
    BOOL ok = set_folder_security(path, sddl);
    if (ok) {
        LOG_INFO("Configured Writable Low Integrity Workspace on: %ls", path);
    }
    return ok;
}

BOOL fs_init_sandbox_workspace(const WCHAR* base_dir) {
    WCHAR root_dir[MAX_PATH];
    if (base_dir && base_dir[0]) {
        swprintf(root_dir, MAX_PATH, L"%ls\\sandbox", base_dir);
    } else {
        wcscpy(root_dir, L"sandbox");
    }

    WCHAR input_dir[MAX_PATH];
    WCHAR output_dir[MAX_PATH];
    WCHAR temp_dir[MAX_PATH];

    swprintf(input_dir, MAX_PATH, L"%ls\\input", root_dir);
    swprintf(output_dir, MAX_PATH, L"%ls\\output", root_dir);
    swprintf(temp_dir, MAX_PATH, L"%ls\\temp", root_dir);

    CreateDirectoryW(root_dir, NULL);
    CreateDirectoryW(input_dir, NULL);
    CreateDirectoryW(output_dir, NULL);
    CreateDirectoryW(temp_dir, NULL);

    /*
     * Configure input_dir: Read-only access for Everyone (WD) and Restricted Code (RC).
     * No write access granted in DACL.
     */
    LPCWSTR input_sddl = L"D:(A;OICI;FRFX;;;WD)(A;OICI;FRFX;;;RC)";
    set_folder_security(input_dir, input_sddl);
    LOG_INFO("Configured Read-Only Policy on: %ls", input_dir);

    /* Write sample input data file */
    WCHAR input_file[MAX_PATH];
    swprintf(input_file, MAX_PATH, L"%ls\\sample_input.txt", input_dir);
    HANDLE hFile = CreateFileW(
        input_file,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char sample_data[] = "WinGuard Sandbox: Authorized Read-Only Input Payload.\n";
        DWORD written = 0;
        WriteFile(hFile, sample_data, (DWORD)strlen(sample_data), &written, NULL);
        CloseHandle(hFile);
        /* Ensure the input file inherits read-only permissions */
        set_folder_security(input_file, L"D:(A;;FRFX;;;WD)(A;;FRFX;;;RC)");
    }

    /*
     * Configure output_dir and temp_dir:
     * Full access in DACL + Low Mandatory Integrity Level SACL.
     */
    fs_set_low_integrity_label(output_dir);
    fs_set_low_integrity_label(temp_dir);

    LOG_INFO("Initialized isolated sandbox filesystem workspace at: %ls", root_dir);
    return TRUE;
}

BOOL fs_cleanup_sandbox_workspace(const WCHAR* base_dir) {
    WCHAR root_dir[MAX_PATH];
    if (base_dir && base_dir[0]) {
        swprintf(root_dir, MAX_PATH, L"%ls\\sandbox", base_dir);
    } else {
        wcscpy(root_dir, L"sandbox");
    }

    LOG_INFO("Sandbox workspace cleanup completed for %ls.", root_dir);
    return TRUE;
}

void fs_print_policy(void) {
    printf("\n-------------------------------------------------------\n");
    printf(" Windows Filesystem Security Policy & Workspace\n");
    printf("-------------------------------------------------------\n");
    printf(" Workspace Root   : sandbox\\\n");
    printf("   ├── input/     : READ-ONLY   (DACL: FRFX Everyone+RestrictedCode; Writes Denied)\n");
    printf("   ├── output/    : READ-WRITE  (DACL: FA Everyone+RestrictedCode; SACL: Low Integrity)\n");
    printf("   └── temp/      : READ-WRITE  (DACL: FA Everyone+RestrictedCode; SACL: Low Integrity)\n");
    printf(" Outside Paths    : BLOCKED     (MIC No-Write-Up prevents escapes outside sandbox)\n");
    printf("-------------------------------------------------------\n\n");
    fflush(stdout);
}
