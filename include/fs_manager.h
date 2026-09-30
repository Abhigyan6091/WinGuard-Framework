#ifndef WINGUARD_FS_MANAGER_H
#define WINGUARD_FS_MANAGER_H

#include <windows.h>
#include <stdbool.h>

/**
 * Initializes the isolated sandbox filesystem hierarchy:
 *   <base_dir>/sandbox/input   (READ-ONLY to Low Integrity)
 *   <base_dir>/sandbox/output  (READ-WRITE to Low Integrity via Mandatory Label)
 *   <base_dir>/sandbox/temp    (READ-WRITE to Low Integrity via Mandatory Label)
 * 
 * Applies Windows NTFS Mandatory Label SACL (S:(ML;OICI;NW;;;LW)) to output and temp
 * so that Low Integrity sandboxed processes can write to them while being blocked
 * from writing to input/ or anywhere outside the sandbox.
 */
BOOL fs_init_sandbox_workspace(const WCHAR* base_dir);

/**
 * Applies a Low Integrity Mandatory Label SACL to the specified path
 * with container and object inheritance.
 */
BOOL fs_set_low_integrity_label(const WCHAR* path);

/**
 * Removes temporary files from sandbox workspace.
 */
BOOL fs_cleanup_sandbox_workspace(const WCHAR* base_dir);

/**
 * Prints the filesystem policy configuration and directory mappings.
 */
void fs_print_policy(void);

#endif /* WINGUARD_FS_MANAGER_H */
