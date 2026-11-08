# Documentation

## Contents
- [`VM::detect()`](#vmdetect)
- [`VM::percentage()`](#vmpercentage)
- [`VM::brand()`](#vmbrand)
- [`VM::check()`](#vmcheck)
- [`VM::add_custom()`](#vmadd_custom)
- [`VM::type()`](#vmtype)
- [`VM::conclusion()`](#vmconclusion)
- [`VM::detected_count()`](#vmdetected_count)
- [`(Advanced) VM::flag_to_string()`](#advanced-vmflag_to_string)
- [`(Advanced) VM::detected_enums()`](#advanced-vmdetected_enums)
- [vmaware struct](#vmaware-struct)
- [Notes](#notes)
- [Flag table](#flag-table)
- [Brand table](#brand-table)
- [Setting flags](#setting-flags)
- [Variables](#variables)
- [CLI documentation](#cli-documentation)


<br>

## `VM::detect()`

This is basically the main function you're looking for, which returns a bool. If no parameter is provided, all the recommended checks will be performed. You can optionally set which techniques are used.

```cpp
#include "vmaware.hpp"

int main() {
    /**
     * The basic way to detect a VM where the default checks will 
     * be performed. This is the recommended usage of the lib.
     */ 
    bool is_vm = VM::detect();


    /**
     * This does the exact same as above, but as an explicit alternative.
     */ 
    bool is_vm2 = VM::detect(VM::DEFAULT);


    /**
     * All checks are performed including techniques that are
     * disabled by default for a viariety of reasons. If you 
     * want all techniques for the sake of completeness, then 
     * you can use this flag but remember that there may be potential 
     * performance bottlenecks and an increase in false positives.
     */ 
    bool is_vm3 = VM::detect(VM::ALL);


    /**
     * This will raise the detection threshold above the default level.
     * Use this if you want to be extremely sure if it's a VM, but this 
     * increases the chance of a false negative. Use VM::percentage() 
     * for a more precise result if you want.
     */ 
    bool is_vm4 = VM::detect(VM::HIGH_THRESHOLD);


    /**
     * Essentially means only the CPU brand, hypervisor string, and hypervisor bit techniques 
     * should be performed. Note that the less technique flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead. Also, read the flag table
     * at the end of this doc file for a full list of technique flags.
     */
    bool is_vm5 = VM::detect(VM::CPU_BRAND, VM::HYPERVISOR_STR, VM::HYPERVISOR_BIT);


    /**
     * If you want to disable any technique for whatever reason, use VM::DISABLE(...).
     * This code snippet essentially means "perform all the default flags, but only 
     * disable the VM::TIMER technique". 
     */ 
    bool is_vm6 = VM::detect(VM::DISABLE(VM::TIMER));


    /**
     * Same as above, but you can disable multiple techniques at the same time.
     */ 
    bool is_vm7 = VM::detect(VM::DISABLE(VM::VMID, VM::TIMER, VM::FIRMWARE));


    /**
     * This is just an example to show that you can use a combination of 
     * different flags and non-technique flags with the above examples. 
     */ 
    bool is_vm8 = VM::detect(VM::DEFAULT, VM::HIGH_THRESHOLD, VM::DISABLE(VM::TIMER, VM::VMID));
}
```

<br>

## `VM::percentage()`
This will return a `std::uint8_t` between 0 and 100. It'll return the certainty of whether it has detected a VM based on all the techniques available as a percentage.

```cpp
#include "vmaware.hpp"
#include <iostream>
#include <cstdint>

int main() {
    // uint8_t and unsigned char works too
    std::uint8_t percent = VM::percentage();

    if (percent == 100) {
        std::cout << "Definitely a VM!\n";
    } else if (percent == 0) {
        std::cout << "Definitely NOT a VM\n";
    } else {
        std::cout << "Unsure if it's a VM\n";
    }

    // converted to int for console character encoding reasons
    std::cout << "percentage: " << static_cast<int>(percent) << "%\n"; 

    return 0;
}
```

> [!NOTE]
> You can use the same flag system as shown with `VM::detect()` for this function.

<br>

## `VM::brand()`
This will essentially return the VM brand as a `std::string`. All the brands and brand alias variables are listed [here](#brand-table)

If none were detected, it will return `Unknown`. It should be noted that it is not always possible to determine the VM brand, even if VMAware detects that it is running on a VM.

```cpp
#include "vmaware.hpp"
#include <string>

int main() {
    std::string result = VM::brand();

    if (result == "KVM") {
        // do KVM specific stuff
    } else if (result == "VirtualBox") {
        // you get the idea
    } else if (result == brands::VMWARE) {
        // having manual string comparisons like the two
        // previous ones can lead to typos which will 
        // make the whole check completely redundant.
        // So the lib provides hardcoded string variables 
        // as aliases to avoid these kinds of situations. 
        // They are located in the aforementioned brand table
    }

    return 0;
}
```


On rare occasions, VMAware might detect signs of multiple brands, which might cause a conflicting output. 
To prevent this, you can use the `VM::MULTIPLE` flag that returns a **message** rather than a **VM brand string**. 
For example, if it found 2 conflicting brands, it will return `VMware or VirtualBox`.


```cpp
#include "vmaware.hpp"
#include <string>

int main() {
    // format: "vmbrand1 or vmbrand2 [or vmbrandx...]"
    std::string result = VM::brand(VM::MULTIPLE);

    // example output: "VMware or Bochs"
    std::cout << result << "\n";

    // Keep in mind that there's no limit to how many conflicts there can be.
    // And if there's no conflict, it'll revert back to giving the brand string
    // normally as if the VM::MULTIPLE wasn't there

    return 0;
}
```

> [!NOTE]
> You can use the same flag system as shown with `VM::detect()` for `VM::brand()`.

> [!IMPORTANT]
> `VM::MULTIPLE` has no effect for any other function other than `VM::brand()`.


<br>

## `VM::check()`
This takes a single technique argument and returns a `bool`. It essentially returns whether the given technique detected a VM or not.


```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::check(VM::VMID)) {
        std::cout << "VMID technique detected a VM!\n";
    }

    if (VM::check(VM::HYPERVISOR_BIT)) {
        std::cout << "Hypervisor bit is set, most definitely a VM!\n";
    }

    return 0;
}
```

<br>

## `VM::add_custom()`
This function allows you to add your own custom VM detection techniques to the scoring system. 
The first parameter is the percentage score (0 to 100) of how likely it's a VM if your custom code returns `true`, and the second parameter should either be a lambda, a function pointer, or a `std::function<bool()>`

```cpp
// Example 1 with function pointers

bool new_technique() {
    // add your VM detection code here
    return true; 
}

VM::add_custom(50, new_technique);
```

```cpp
// Example 2 with lambdas

VM::add_custom(50, []() -> bool { 
    // add your VM detection code here
    return true; 
});

auto new_technique = []() -> bool { 
    // add your VM detection code here
    return true;
}

VM::add_custom(50, new_technique);
```

```cpp
// Example 3 with std::function

std::function<bool()> new_technique = []() -> bool {
    // add your VM detection code here
    return true;
};

VM::add_custom(50, new_technique);
```

<br>

## `VM::type()`
This will return the VM type (or architecture) as a `std::string` based on the brand found. The possible return values are listed [here](#brand-table) in the `type` column.

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    // example output: VirtualBox is a Hypervisor (type 2) VM
    std::cout << VM::brand() << " is a " << VM::type() << " VM\n";
    return 0;
}
```


<br>

## `VM::conclusion()`
This will return the "conclusion" message of what the overall result is as a `std::string`. By default, there are 2 possible outputs:
- `Running on bare metal`
- `Running inside a [brand] VM`

The `[brand]` part might contain a brand or may as well be empty, depending on whether a brand has been found. Additionally, you can extend this by adding the `VM::DYNAMIC` flag, which will now allow much more variadic potential outputs:
- `Running on bare metal`
- `Very unlikely a [brand] VM`
- `Unlikely a [brand] VM`
- `Potentially a [brand] VM`
- `Might be a [brand] VM`
- `Likely a [brand] VM`
- `Very likely a [brand] VM`
- `Running inside a [brand] VM`


<br>

## `VM::detected_count()`
This will fetch the number of techniques that have been detected as a `std::uint8_t`.

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    std::uint8_t count = VM::detected_count();

    // output: 7 techniques were detected
    std::cout << count << " techniques were detected" << "\n"; 

    return 0;
}
```

<br>

## (Advanced) `VM::flag_to_string()`

<details>
<summary>Show</summary>

This will take a technique flag enum as an argument and return the string version of it. For example:

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    std::string name = VM::flag_to_string(VM::VMID);

    // output: VM::VMID 
    std::cout << "VM::" << name << "\n"; 

    return 0;
}
```

The reason why this exists is because it can be useful for debugging and infodumping purposes. It should be noted that the "VM::" part is not included in the string output, so that's based on the programmer's choice if it should remain in the string or not. The example given above is obviously useless since the whole code can be manually handwritten, but the function is especially convenient if it's being used with [`VM::technique_vector`](#variables). For example:

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    // this will loop through all the enums in the technique_vector variable,
    // and then checks each of them and outputs the enum that was detected
    for (const auto technique_enum : VM::technique_vector) {
        if (VM::check(technique_enum)) {
            const std::string name = VM::flag_to_string(technique_enum);
            std::cout << "VM::" << name << " was detected\n";
        }
    }

    return 0;
}
```

</details>

<br>

## (Advanced) `VM::detected_enums()`

<details>
<summary>Show</summary>

This is a function that will return a vector of all the technique flags that detected a VM. The return type is `std::vector<VM::enum_flags>`, and it's designed to give a more programmatic overview of the result. 

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    std::vector<VM::enum_flags> flag_list = VM::detected_enums();

    for (const auto flag : flag_list) {
        std::cout << "VM::" << VM::flag_to_string(flag) << " was detected" << "\n"; 
    }

    return 0;
}
```

</details>

<br>

# vmaware struct
If you prefer having an object to store all the relevant information about the program's environment instead of calling static member functions, you can use the `VM::vmaware` struct:

```cpp
struct vmaware {
    std::string brand;
    std::string type;
    std::string conclusion;
    bool is_vm;
    std::uint8_t percentage;
    std::uint8_t detected_count;
    std::uint8_t technique_count;
    std::vector<enum_flags> detected_techniques;
    std::vector<std::string> detected_technique_strings;
    std::vector<enum_flags> disabled_techniques;
}; 
```

Example:
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    VM::vmaware vm;

    std::cout << "Is this a VM? = " << vm.is_vm << "\n";
    std::cout << "How many techniques detected a VM? = " << vm.detected_count << "%\n";
    std::cout << "What's the VM's type? = " << vm.type << "%\n";
    std::cout << "What's the overview in a human-readable message?" << vm.conclusion << "\n";
}
```

The caller can use the `VM::vmaware` struct to capture a single snapshot that owns the data too, acting as memoization.

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    // Runs all detections once; caller owns the immutable result
    VM::vmaware vm;

    if (vm.is_vm) {
        std::cout << "VM Detected!\n";
        std::cout << "Brand: " << vm.brand << "\n";
        std::cout << "Type:  " << vm.type << "\n";
        std::cout << "Certainty: " << (int)vm.percentage << "%\n";
    } else {
        std::cout << "Running on bare metal\n";
    }
}
```

> [!NOTE]
> The flag system is compatible for the struct constructor.

<br>

# Notes
❌ Do NOT rely on the percentage to determine whether you're in a VM. Use VM::detect() instead for that job.

> [!TIP]
> It should also be mentioned that it's recommended for the end-user to create a wrapper around the header file. C++ compilation is notoriously slow compared to C or other systems programming languages, and recompiling the header over and over again is a time waste, especially considering there's around 10k lines of code in it. This is incredibly unreliable and cumbersome for large-scale projects utilising the lib. If you have a build configuration that supports header dependency handling or [incremental compilation](https://en.wikipedia.org/wiki/Incremental_compiler) (which is present in most build systems such as CMake), you can fix the issue by doing something like this:
> ```cpp
> // wrapper.hpp
> #include <string>
> 
> namespace wrapper {
>     bool is_this_a_vm();
>     std::string vm_brand_name();
> }
> ```
> 
> ```cpp
> // wrapper.cpp
> #include "vmaware.hpp"
> #include "wrapper.hpp"
> 
> bool wrapper::is_this_a_vm() {
>     return VM::detect();
> }
> 
> std::string wrapper::vm_brand_name() {
>     return VM::brand();
> }
> ```
> 
> ```cpp
> // something.cpp
> #include "wrapper.hpp"
> 
> void something() {
>     if (wrapper::is_this_a_vm()) {
>         std::cout << wrapper::vm_brand_name() << "\n";
>     }
> }
> ```
> 
> This wrapper structure would prevent any avoidable recompilations as opposed to potentially recompiling the vmaware.hpp file for every build that modifies the source that #includes the lib, especially if there's a deep hierarchy of file dependencies within your project.

<br>

# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.

| Icon | Platform |
| --- | --- |
| 🐧 | Linux |
| 🪟 | Windows |
| 🍏 | macOS |

<!-- START OF TECHNIQUE DOCUMENTATION -->

| Flag alias | Description | Supported platforms | Certainty | Admin? | 32-bit only? | Notes | Code implementation |
| ---------- | ----------- | ------------------- | --------- | ------ | ------------ | ----- | ------------------- |
<!-- END OF TECHNIQUE DOCUMENTATION -->

<br>

# Brand table

This is the table of all the brands the lib supports.

| String | Variable alias | VM type | Notes |
| ------ | -------------- | ------- | ----- |
| Unknown | `brands::NULL_BRAND` | Unknown | This is the default brand it returns if none were found |
| VirtualBox | `brands::VBOX` | Hypervisor (type 2) |  |
| VMware | `brands::VMWARE` | Hypervisor (type 2) |  |
| VMware Express | `brands::VMWARE_EXPRESS` | Hypervisor (type 2) |  |
| VMware ESX | `brands::VMWARE_ESX` | Hypervisor (type 1) |  |
| VMware GSX | `brands::VMWARE_GSX` | Hypervisor (type 2) |  |
| VMware Workstation | `brands::VMWARE_WORKSTATION` | Hypervisor (type 2) |  |
| VMware Fusion | `brands::VMWARE_FUSION` | Hypervisor (type 2) |  |
| VMware (with VmwareHardenedLoader) | `brands::VMWARE_HARD` | Hypervisor (type 2) | See the [repository](https://github.com/hzqst/VmwareHardenedLoader) |
| bhyve | `brands::BHYVE` | Hypervisor (type 2) |  |
| KVM | `brands::KVM` | Hypervisor (type 1) |  |
| QEMU | `brands::QEMU` | Emulator/Hypervisor (type 2) |  |
| QEMU+KVM | `brands::QEMU_KVM` | Hypervisor (type 1) |  |
| KVM Hyper-V Enlightenment | `brands::KVM_HYPERV` | Hypervisor (type 1) |  |
| QEMU+KVM Hyper-V Enlightenment | `brands::QEMU_KVM_HYPERV` | Hypervisor (type 1) |  |
| Microsoft Hyper-V | `brands::HYPERV` | Hypervisor (type 1) |  |
| Microsoft Virtual PC/Hyper-V | `brands::HYPERV_VPC` | Hypervisor (either type 1 or 2) |  |
| Parallels | `brands::PARALLELS` | Hypervisor (type 2) |  |
| Xen HVM | `brands::XEN` | Hypervisor (type 1) |  |
| ACRN | `brands::ACRN` | Hypervisor (type 1) |  |
| QNX hypervisor | `brands::QNX` | Hypervisor (type 1) |  |
| Hybrid Analysis | `brands::HYBRID` | Sandbox |  |
| Sandboxie | `brands::SANDBOXIE` | Sandbox |  |
| Docker | `brands::DOCKER` | Container |  |
| Wine | `brands::WINE` | Compatibility layer |  |
| Virtual PC  | `brands::VPC` | Hypervisor (type 2) |  |
| Anubis | `brands::ANUBIS` | Sandbox |  |
| JoeBox | `brands::JOEBOX` | Sandbox |  |
| ThreatExpert | `brands::THREATEXPERT` | Sandbox |  |
| CWSandbox | `brands::CWSANDBOX` | Sandbox |  |
| Comodo | `brands::COMODO` | Sandbox |  |
| Bochs | `brands::BOCHS` | Emulator |  |
| NetBSD NVMM | `brands::NVMM` | Hypervisor (type 2) |  |
| OpenBSD VMM | `brands::BSD_VMM` | Hypervisor (type 2) |  |
| Intel HAXM | `brands::INTEL_HAXM` | Hypervisor (type 1) |  |
| Unisys s-Par | `brands::UNISYS` | Partitioning Hypervisor |  |
| Lockheed Martin LMHS  | `brands::LMHS` | Hypervisor (unknown type) | Yes, you read that right. The lib can detect VMs running on US military fighter jets, apparently. |
| Cuckoo | `brands::CUCKOO` | Sandbox |  |
| BlueStacks | `brands::BLUESTACKS` | Emulator |  |
| Jailhouse | `brands::JAILHOUSE` | Partitioning Hypervisor |  |
| Apple VZ | `brands::APPLE_VZ` | Unknown |  |
| Intel KGT (Trusty) | `brands::INTEL_KGT` | Hypervisor (type 1) |  |
| Microsoft Azure Hyper-V | `brands::AZURE_HYPERV` | Hypervisor (type 1) |  |
| SimpleVisor | `brands::SIMPLEVISOR` | Hypervisor (type 1) |  |
| Hyper-V root partition (host system, not an actual VM) | `brands::HYPERV_ARTIFACT` | Host machine | Windows Hyper-V has a tendency to modify host hardware values with VM values. In other words, this brand signifies that you're running on a host system, but the Hyper-V that's installed (either by default or manually by the user) is misleadingly making the whole system look like it's in a VM when in reality it's not. <br><br> For more information, refer to [this graph](https://github.com/NotRequiem/VMAware/blob/main/assets/hyper-x/v5/Hyper-X_version_5.drawio.png). |
| User-mode Linux | `brands::UML` | Paravirtualised/Hypervisor (type 2) |  |
| IBM PowerVM | `brands::POWERVM` | Hypervisor (type 1) |  |
| OpenStack (KVM) | `brands::OPENSTACK` | Hypervisor (type 1) |  |
| KubeVirt (KVM) | `brands::KUBEVIRT` | Hypervisor (type 1) |  |
| AWS Nitro System EC2 (KVM-based) | `brands::AWS_NITRO` | Hypervisor (type 1) |  |
| Podman | `brands::PODMAN` | Container |  |
| WSL | `brands::WSL` | Hybrid Hyper-V (type 1 and 2) | This is a type 1 at the fundamental level, but WSL has components that are reminiscent of type 2 VM designs to an extent. |
| OpenVZ | `brands::OPENVZ` | Container |  |
| ANY.RUN | N/A | Sandbox | Removed from the lib, available only in the CLI due to ethical reasons. |
| Barevisor | `brands::BAREVISOR` | Hypervisor (type 1) |  |
| HyperPlatform | `brands::HYPERPLATFORM` | Hypervisor (type 1) |  |
| MiniVisor | `brands::MINIVISOR` | Hypervisor (type 1) |  |
| Intel TDX | `brands::INTEL_TDX` | Trusted Domain |  |
| LKVM | `brands::LKVM` | Hypervisor (type 1) |  |
| AMD SEV | `brands::AMD_SEV` | VM encryptor |  |
| AMD SEV-ES | `brands::AMD_SEV_ES` | VM encryptor |  |
| AMD SEV-SNP | `brands::AMD_SEV_SNP` | VM encryptor |  |
| Neko Project II | `brands::NEKO_PROJECT` | Emulator |  | 
| Google Compute Engine (KVM) | `brands::GCE` | Cloud VM service |  |
| NoirVisor | `brands::NOIRVISOR` | Hypervisor (type 1) |  |
| Qihoo 360 Sandbox | `brands::QIHOO` | Sandbox |  |
| nsjail | `brands::NSJAIL` | Process isolator |  |
| DBVM | `brands::DBVM` | Hypervisor (type 1) | See the [Cheat Engine's Website](https://www.cheatengine.org/aboutdbvm.php) |
| UTM | `brands::UTM` | Hypervisor (type 2) |  |
| Compaq FX!32 | `brands::COMPAQ` | Emulator |  |
| Insignia RealPC | `brands::INSIGNIA` | Emulator |  |
| Connectix Virtual PC | `brands::CONNECTIX` | Emulator |
    

<br>

# Setting flags
| Flag | Description | Specific to |
|------|-------------|-------------|
| `VM::ALL` | This will enable all the technique flags, including checks that are disabled by default. |  |
| `VM::DEFAULT` | This represents a range of flags which are enabled if no default argument is provided. |
| `VM::MULTIPLE` | This will basically return a `std::string` message of which brands could be involved. For example, it could return "`VMware or VirtualBox`" instead of having a single brand string output. | VM::brand() |   
| `VM::HIGH_THRESHOLD` | This will set the threshold bar to confidently detect a VM by 2x higher. | VM::detect() and VM::percentage() |
| `VM::DYNAMIC` | This will add 8 options to the conclusion message rather than 2, each with their own varying likelihoods. | VM::conclusion() |
| `VM::EXPERIMENTAL` | This will disable all VM detection techniques marked as experimental. | VM::detect() |
| `VM::NULL_ARG` | Does nothing, meant as a placeholder flag mainly for CLI purposes. It's best to ignore this.|  |

<br>

# Variables
| Variable | Type | Description |
|----------|------|-------------|
| `VM::technique_count` | `std::uint16_t` | This will store the number of VM detection techniques |
| `VM::technique_vector` | `std::vector<std::uint8_t>` | This will store all the technique macros as a vector. Useful if you're trying to loop through all the techniques for whatever operation you're performing. |

<br>

# CLI documentation
| Shorthand | Full command | Description |
|-----------|--------------|-------------|
| -h | --help | Prints the help menu |
| -v | --version | Prints the version and miscellaneous details |
| -d | --detect | Prints the VM detection result (1 = VM, 0 = bare metal) |
| -s | --stdout | Returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = bare metal) |
| -b | --brand | Prints the most likely brand |
| -l | --brand-list | Prints all the possible VM brand strings the CLI supports |
| -c | --conclusion | Prints the conclusion message string |
| -p | --percent | Prints the VM likeliness percentage between 0 and 100 |
| -n | --number | Prints the number of VM detection techniques it can perform |
| -t | --type | Returns the VM type (if a VM was found) |
| -o | --output | Set the output path for files, specifically with the --json command |
|    | --disable-notes | No notes will be provided |
|    | --high-threshold | A higher threshold bar for a VM detection will be applied |
|    | --no-ansi | Removes all the ANSI encodings (color and text style). This is added due to some terminals not supporting ANSI escape codes while cluttering the output |
|    | --dynamic | Allow the conclusion message to be dynamic (8 possibilities instead of only 2) |
|    | --verbose | Add more information to the output  |
|    | --enums | Display the technique enum name used by the lib |
|    | --detected-only | Only display the techniques that were detected |
|    | --experimental | Disable experimental techniques |
|    | --json | Output a json-formatted file of the results |

> [!NOTE]
> If you want a general result with the default settings, do not put any arguments. This is the intended way to use the CLI tool.
> 