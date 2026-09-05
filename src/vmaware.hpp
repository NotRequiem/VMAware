/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ Experimental post-2.8.1 (August 2026)
 *
 *  C++ VM detection library
 *
 *  - Developed by: Requiem (https://github.com/NotRequiem)
 *  - Former developer and creator: kernelwernel (https://github.com/kernelwernel)
 *  - Contributed by:
 *      - Alex (https://github.com/greenozon)
 *      - Marek Knápek (https://github.com/MarekKnapek)
 *      - Vladyslav Miachkov (https://github.com/fameowner99)
 *      - Alan Tse (https://github.com/alandtse)
 *      - Georgii Gennadev (https://github.com/D00Movenok)
 *      - utoshu (https://github.com/utoshu)
 *      - Jyd (https://github.com/jyd519)
 *      - dmfrpro (https://github.com/dmfrpro)
 *      - Pierre-Étienne Messier (https://github.com/pemessier)
 *      - Teselka (https://github.com/Teselka)
 *      - Kyun-J (https://github.com/Kyun-J)
 *      - luukjp (https://github.com/luukjp)
 *      - Lorenzo Rizzotti (https://github.com/Dreaming-Codes) 
 *      - virtfunc (https://github.com/virtfunc)
 *      - Wiisus (https://github.com/wiisus)
 *      - Max Ufer (https://github.com/Manny684)
 *      - everdox (https://github.com/everdox)
 *  - Repository: https://github.com/NotRequiem/VMAware
 *  - Docs: https://github.com/NotRequiem/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/NotRequiem/VMAware#credits-and-contributors-%EF%B8%8F
 *  - License: MIT
 *
 *
 * ============================== SECTIONS ==================================
 * - enums for publicly accessible techniques  => line 640
 * - struct for internal cpu operations        => line 919
 * - struct for internal memoization           => line 3090
 * - struct for internal utility functions     => line 4139
 * - struct for internal core components       => line 14624
 * - start of VM detection technique list      => line 5442
 * - start of public VM detection functions    => line 15017
 * - start of externally defined variables     => line 15734
 *
 *
 * ============================== EXAMPLE ===================================
 * #include "vmaware.hpp"
 * #include <iostream>
 * 
 * int main() {
 *     if (VM::detect()) {
 *         std::cout << "Virtual machine detected!" << "\n";
 *     } else {
 *         std::cout << "Running on bare metal" << "\n";
 *     }
 * 
 *     std::cout << "VM name: " << VM::brand() << "\n";
 *     std::cout << "VM type: " << VM::type() << "\n";
 *     std::cout << "VM certainty: " << (int)VM::percentage() << "%" << "\n";
 * }
 * 
 *
 * ========================== CODE DOCUMENTATION =============================
 *
 *
 * Welcome! This is just a preliminary text to lay the context of how it works, 
 * how it's structured, and to guide anybody who's trying to understand the whole code. 
 * Reading over 10k+ lines of other people's C++ code is obviously not an easy task, 
 * and that's perfectly understandable. We'd struggle as well if we were in your position
 * while not even knowing where to start. So here's a more human-friendly explanation:
 * 
 * 
 * Firstly, the lib is completely static, meaning that there's no need for struct 
 * constructors to be initialized (unless you're using the VM::vmaware struct).
 * The main focus of the lib are the tables:
 *  - the TECHNIQUE table stores all the VM detection technique information in a std::array 
 * 
 *  - the BRAND table stores every VM brand as a std::array as well, but as a scoreboard. 
 *    This means that if a VM detection technique has detected a VM brand, that brand will have an
 *    incremented score. After every technique is run, the brand with the highest score
 *    is chosen as the officially detected brand. 
 * 
 * The techniques are all static functions, which all return a boolean. There are a few 
 * categories of techniques that target vastly different things such as OS queries, CPU
 * values, other hardware values, firmware data, and system files just to name a few. 
 * 
 * 
 * Secondly, there are multiple modules in the lib that are combined to integrate with
 * the functionalities needed:
 *    - core module:
 *        This contains many important components such as the aforementioned tables, 
 *        the standard structure for how VM techniques are organised, functionalities 
 *        to run all the techniques in the technique table, functionalities to run
 *        custom-made techniques by the user, and an argument handler based on the 
 *        argument input by the user.
 *
 *    - cpu module:
 *        As the name suggests, this contains functionalities for the CPU. There are
 *        many techniques that utilise some kind of low-level CPU interaction, so 
 *        this module was added to further standardise it.
 * 
 *    - memo module:
 *        This contains functionalities for memoizing technique results (not to be
 *        confused with "memorization"). More specifically, this allows us to cache 
 *        a technique result in a table where each entry contains a technique and its
 *        result. This allows us to avoid re-running techniques which happens a lot
 *        internally. Some techniques are costlier than others in terms of 
 *        performance, so this is a crucial module that allows us to save a lot of
 *        time. Additionally, it contains other memoization caches for various other
 *        things for convenience. 
 * 
 *    - util module:
 *        This contains many utility functionalities to be used by the techniques.
 *        Examples of functionalities include file I/O, registries, permission 
 *        checks, system commands, debugs, OS queries, Hyper-X, and so on. 
 * 
 * 
 * Thirdly, We'll explain in this section how all of these facets of the lib interact with 
 * each other. Let's take an example with VM::detect(), where it returns a boolean true or 
 * false if a VM has been detected or not. The chain of steps it takes goes like this:
 *    1. The function tries to handle the user arguments (if there's 
 *       any), and generates a std::bitset. This bitset has a length of 
 *       every VM detection technique + settings, where each bit 
 *       corresponds to whether this technique will be run or not, 
 *       and which settings were selected. 
 * 
 *    2. After the bitset has been generated, this information is then 
 *       passed to the core module of the lib. It analyses the bitset, 
 *       and runs every VM detection technique that has been selected, 
 *       while ignoring the ones that weren't (by default most of them 
 *       are already selected anyway). The function that does this 
 *       mechanism is core::run_all()
 * 
 *    3. While the core::run_all() function is being run, it checks if 
 *       each technique has already been memoized or not. If it has, 
 *       retrieve the result from the cache and move to the next technique. 
 *       If it hasn't, run the technique and cache the result in the 
 *       cache table. 
 * 
 *    4. After every technique has been executed, this generates a 
 *       uint16_t score. Every technique has a score value between 0 to 
 *       100, and if a VM is detected then this score is accumulated to 
 *       a total. If the total is above 150, that means it's a VM[1]. 
 * 
 * 
 * There are other functions such as VM::brand(), which returns a std::string of the most 
 * likely brand that your system is running on. It has a bit of a different mechanism:
 *    1. Same as step 1 in VM::detect()
 * 
 *    2. Check if the majority of techniques have been run already and stored
 *       in the cache. If not, invoke core::run_all(). The reason why this is
 *       important is because a lot of techniques increment a point for its 
 *       respected brand that was detected. For example, if the VM::QEMU_USB
 *       technique has detected a VM, it'll add a score to the QEMU brand in
 *       the scoreboard. If no technique were run, then there's no way to
 *       populate the scoreboard with any points. After every VM detection 
 *       technique has been invoked/retrieved, the brand scoreboard is now
 *       ready to be analysed.
 * 
 *    3. Create a filter for the scoreboard, where every brand that has a score
 *       of 0 are erased for abstraction purposes. Now the scoreboard is only
 *       populated with relevant brands where they all have at least a single
 *       point. These are the contenders for which brand will be outputted.
 *       Think of it as fetching candidates with potential while discarding
 *       those that don't.
 * 
 *    4. Merge certain brand combinations together. For example, Azure's cloud 
 *       is based on Hyper-V, but Hyper-V may have a higher score due to the 
 *       prevalence of it in a practical setting, which will put Azure to the 
 *       side. In reality, there should be an indication that Azure is involved
 *       since it's a better idea to let the user know that the brand is "Azure 
 *       Hyper-V" instead of just "Hyper-V". So what this step does is "merge" 
 *       the brands together to form a more accurate idea of the brand(s) involved.
 * 
 *    5. After all of this, the scoreboard is sorted in descending order, where
 *       the brands with the highest points are now selected as the official 
 *       output of the VM::brand() function.
 * 
 *    6. The result is then cached in the memo module, so if another function
 *       invokes VM::brand() again, the result is retrieved from the cache 
 *       without needing to run all of the previous steps again.
 *      
 * (NOTE: it's a bit more complicated than this, but that's the gist of how this function works)
 * 
 * Most of the functions provided usually depend on the 2 techniques covered. 
 * And they serve as a functionality base for other components of the lib.
 *      
 *  
 *  [1]: If the user has provided a setting argument called VM::HIGH_THRESHOLD, 
 *       the threshold becomes 300 instead of 150.
 */

#ifndef VMAWARE_HEADER
#define VMAWARE_HEADER

#ifndef VMAWARE_PLATFORM_MACROS_H
#define VMAWARE_PLATFORM_MACROS_H

/* =========================================================================
 * DEBUG DETECTION
 * ========================================================================= */
#ifndef VMAWARE_DEBUG
    #if (defined(_DEBUG) && _DEBUG) || (defined(DEBUG) && DEBUG) || (!defined(NDEBUG) && !defined(_DEBUG) && !defined(DEBUG))
        #define VMAWARE_DEBUG 1
    #else
        #define VMAWARE_DEBUG 0
    #endif
#endif

/* =========================================================================
 * OPERATING SYSTEM DETECTION
 * ========================================================================= */
#if defined(_WIN32) || defined(_WIN64)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    
    #define VMAWARE_WINDOWS 1
    #define VMAWARE_LINUX 0
    #define VMAWARE_APPLE 0
#elif (defined(__linux__))
    #define VMAWARE_WINDOWS 0
    #define VMAWARE_LINUX 1
    #define VMAWARE_APPLE 0
#elif (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
    #define VMAWARE_WINDOWS 0
    #define VMAWARE_LINUX 0
    #define VMAWARE_APPLE 1
#else
    #define VMAWARE_WINDOWS 0
    #define VMAWARE_LINUX 0
    #define VMAWARE_APPLE 0
#endif

#if !(VMAWARE_WINDOWS || VMAWARE_LINUX || VMAWARE_APPLE)
    #if defined(_MSC_VER)
        #pragma message("Warning: Unknown OS detected, tests will be severely limited")
    #else
        #warning "Unknown OS detected, tests will be severely limited"
    #endif
#endif

/* =========================================================================
 * COMPILER DETECTION 
 * ========================================================================= */
#if defined(__clang__)
    #define VMAWARE_CLANG 1
    #define VMAWARE_GCC   0
    #define VMAWARE_MSVC  0
#elif defined(__GNUC__) || defined(__GNUG__)
    #define VMAWARE_CLANG 0
    #define VMAWARE_GCC   1
    #define VMAWARE_MSVC  0
#elif defined(_MSC_VER)
    #define VMAWARE_CLANG 0
    #define VMAWARE_GCC   0
    #define VMAWARE_MSVC  1
#else
    #define VMAWARE_CLANG 0
    #define VMAWARE_GCC   0
    #define VMAWARE_MSVC  0
#endif

/* =========================================================================
 * C++ STANDARD DETECTION
 * ========================================================================= */
#if defined(_MSVC_LANG)
    #define VMAWARE_CPLUSPLUS _MSVC_LANG
#else
    #define VMAWARE_CPLUSPLUS __cplusplus
#endif

#if VMAWARE_CPLUSPLUS >= 202302L
    #define VMAWARE_CPP 23
#elif VMAWARE_CPLUSPLUS >= 202002L
    #define VMAWARE_CPP 20
#elif VMAWARE_CPLUSPLUS >= 201703L
    #define VMAWARE_CPP 17
#elif VMAWARE_CPLUSPLUS >= 201402L
    #define VMAWARE_CPP 14
#elif VMAWARE_CPLUSPLUS >= 201103L
    #define VMAWARE_CPP 11
#elif VMAWARE_CPLUSPLUS >= 199711L
    #define VMAWARE_CPP 98 /* C++98 or C++03 */
#else
    #error "Unsupported C++ standard (pre-C++98 or unknown)."
#endif
    
#if (VMAWARE_CPP < 11)
    #error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for gcc/clang, or '/std:c++20' for MSVC"
#endif
      
/* =========================================================================
 * ARCHITECTURE DETECTION
 * ========================================================================= */
#if defined(_M_ARM64EC) || defined(__arm64ec__)
    #define VMAWARE_ARM64EC 1
#else
    #define VMAWARE_ARM64EC 0
#endif

#if (defined(__x86_64__) || defined(_M_X64)) && !VMAWARE_ARM64EC
    #define VMAWARE_X86_64 1
#else
    #define VMAWARE_X86_64 0
#endif

#if defined(__i386__) || defined(_M_IX86)
    #define VMAWARE_X86_32 1
#else
    #define VMAWARE_X86_32 0
#endif

#if VMAWARE_X86_32 || VMAWARE_X86_64
    #define VMAWARE_X86 1
#else
    #define VMAWARE_X86 0
#endif
    
#if (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_LINUX_COMPILER__) || defined(__arm64__)) && !VMAWARE_ARM64EC
    #define VMAWARE_ARM64 1
#else
    #define VMAWARE_ARM64 0
#endif

#if (defined(__arm__) || defined(_M_ARM)) && !VMAWARE_ARM64
    #define VMAWARE_ARM32 1
#else
    #define VMAWARE_ARM32 0
#endif
    
#if VMAWARE_ARM32 || VMAWARE_ARM64
    #define VMAWARE_ARM 1
#else
    #define VMAWARE_ARM 0
#endif

/* =========================================================================
 * FEATURE TEST MACROS 
 * ========================================================================= */
#if (VMAWARE_CPP >= 20) && defined(__has_include)
    #if __has_include(<source_location>)
        #include <source_location>
    #if defined(__cpp_lib_source_location) && (__cpp_lib_source_location >= 201907L)
        #define VMAWARE_SOURCE_LOCATION_SUPPORTED 1
    #else
        #define VMAWARE_SOURCE_LOCATION_SUPPORTED 0
    #endif
    #else
        #define VMAWARE_SOURCE_LOCATION_SUPPORTED 0
    #endif
#else
    #define VMAWARE_SOURCE_LOCATION_SUPPORTED 0
#endif

/* =========================================================================
 * ATTRIBUTES & SYMBOL VISIBILITY
 * ========================================================================= */
#if (VMAWARE_CPP >= 14)
    #define VMAWARE_DEPRECATED(msg) [[deprecated(msg)]]
#elif VMAWARE_MSVC
    #define VMAWARE_DEPRECATED(msg) __declspec(deprecated(msg))
#elif VMAWARE_GCC || VMAWARE_CLANG
    #define VMAWARE_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
    #define VMAWARE_DEPRECATED(msg)
#endif

#if defined(VMAWARE_SHARED)
    #if (VMAWARE_WINDOWS)
        #if defined(VMAWARE_DLL_EXPORT)
            #define VMAWARE_API __declspec(dllexport)
        #else
            #define VMAWARE_API __declspec(dllimport)
        #endif
    #elif (VMAWARE_GCC || VMAWARE_CLANG)
        #define VMAWARE_API __attribute__((visibility("default")))
    #else
        #define VMAWARE_API
    #endif
#else
    #define VMAWARE_API
#endif

/* =========================================================================
 * CONSTEXPR HELPERS
 * ========================================================================= */
#if (VMAWARE_CPP >= 17) /* Instead of 11 or 14 on purpose */
    #define VMAWARE_CONSTEXPR constexpr
#else
    #define VMAWARE_CONSTEXPR
#endif

#if (VMAWARE_CPP >= 20)
    #define VMAWARE_CONSTEXPR_20 constexpr
#else
    #define VMAWARE_CONSTEXPR_20
#endif

/* =========================================================================
 * INLINING & RESTRICT
 * ========================================================================= */
#if (VMAWARE_MSVC)
    #define VMAWARE_NOINLINE __declspec(noinline)
#elif (VMAWARE_CLANG || VMAWARE_GCC)
    #define VMAWARE_NOINLINE __attribute__((noinline))
#else
    #define VMAWARE_NOINLINE
#endif

#if (VMAWARE_MSVC)
    #define VMAWARE_FORCE_INLINE __forceinline
#elif (VMAWARE_CLANG || VMAWARE_GCC)
    #define VMAWARE_FORCE_INLINE inline __attribute__((always_inline))
#else
    #define VMAWARE_FORCE_INLINE inline
#endif

#if (VMAWARE_MSVC)
    #define VMAWARE_RESTRICT __restrict
#elif (VMAWARE_CLANG || VMAWARE_GCC)
    #define VMAWARE_RESTRICT __restrict__
#else
    #define VMAWARE_RESTRICT
#endif

/* =========================================================================
 * BRANCH PREDICTION & ASSUMPTIONS
 * ========================================================================= */
#if defined(__cpp_attribute_assume) && (__cpp_attribute_assume >= 202207L)
    #define VMAWARE_ASSUME(cond) [[assume(cond)]]
#elif VMAWARE_CLANG
    #define VMAWARE_ASSUME(cond) __builtin_assume(cond)
#elif VMAWARE_MSVC
    #define VMAWARE_ASSUME(cond) __assume(cond)
#elif VMAWARE_GCC && (__GNUC__ >= 13)
    #define VMAWARE_ASSUME(cond) __attribute__((assume(cond)))
#elif VMAWARE_GCC
    #define VMAWARE_ASSUME(cond) do { if (!(cond)) __builtin_unreachable(); } while(0)
#else
    #define VMAWARE_ASSUME(cond) do { (void)sizeof(cond); } while(0) /* Expressions inside VMAWARE_ASSUME must be side-effect-free */
#endif

#if (VMAWARE_GCC || VMAWARE_CLANG)
    #define VMAWARE_LIKELY(x)   (__builtin_expect(!!(x), 1))
    #define VMAWARE_UNLIKELY(x) (__builtin_expect(!!(x), 0))
#else
    #define VMAWARE_LIKELY(x)   (x)
    #define VMAWARE_UNLIKELY(x) (x)
#endif

/* =========================================================================
 * INTRINSIC HEADERS
 * ========================================================================= */
#if defined(_MSC_VER)
    #include <intrin.h>
#elif (VMAWARE_GCC || VMAWARE_CLANG)
    #if (VMAWARE_X86)
        #include <x86intrin.h>
        #include <immintrin.h>
    #endif
#endif

/* =========================================================================
 * PREFETCH CONSTANTS
 * ========================================================================= */
#ifndef _MM_HINT_NTA
    #define _MM_HINT_NTA 0
#endif
    #ifndef _MM_HINT_T0
    #define _MM_HINT_T0 1
#endif
    #ifndef _MM_HINT_T1
    #define _MM_HINT_T1 2
#endif
    #ifndef _MM_HINT_T2
    #define _MM_HINT_T2 3
#endif

/* =========================================================================
 * MEMORY PREFETCH
 * ========================================================================= */
#if (VMAWARE_GCC || VMAWARE_CLANG)
     /* Should work for both x86 and ARM without an x86 guard */
    #define VMAWARE_PREFETCH(ptr, hint) \
                __builtin_prefetch( \
                    const_cast<const void*>(static_cast<const volatile void*>(ptr)), \
                    0, \
                    (hint) \
                )
#elif defined(_MSC_VER)
    #if (VMAWARE_X86)
        #define VMAWARE_PREFETCH(ptr, hint) \
                        _mm_prefetch( \
                            const_cast<const char*>(reinterpret_cast<const volatile char*>(ptr)), \
                            (hint) \
                        )
    #else
        #define VMAWARE_PREFETCH(ptr, hint) ((void)(ptr), (void)(hint))
    #endif
#else
    #define VMAWARE_PREFETCH(ptr, hint) ((void)(ptr), (void)(hint))
#endif

/* =========================================================================
 * ARCHITECTURE-SPECIFIC INTRINSICS
 * ========================================================================= */
#if (VMAWARE_X86)
    #if (VMAWARE_MSVC) || defined(__vectorcall)
        #define VMAWARE_VECTORCALL __vectorcall
    #elif (VMAWARE_CLANG)
        #define VMAWARE_VECTORCALL __attribute__((vectorcall))
    #else
        #define VMAWARE_VECTORCALL
    #endif

    #if (VMAWARE_GCC || VMAWARE_CLANG)
        #define VMAWARE_TARGET_AVX    __attribute__((target("avx")))
        #define VMAWARE_TARGET_AVX2   __attribute__((target("avx2")))
        #define VMAWARE_TARGET_AVX512 __attribute__((target("avx512f")))
    #else
        #define VMAWARE_TARGET_AVX
        #define VMAWARE_TARGET_AVX2
        #define VMAWARE_TARGET_AVX512
    #endif

    #if (VMAWARE_GCC || VMAWARE_CLANG)
        #define VMAWARE_SERIALIZE __attribute__((__target__("serialize")))
    #else
        #define VMAWARE_SERIALIZE
    #endif
#else 
    #define VMAWARE_VECTORCALL
    #define VMAWARE_TARGET_AVX
    #define VMAWARE_TARGET_AVX2
    #define VMAWARE_TARGET_AVX512
    #define VMAWARE_SERIALIZE
#endif

#define VMAWARE_UNUSED(x) ((void)(x))

#if (VMAWARE_CLANG)
    /* This happens because Windows API structures or aliases are typedef'd inside a local scope (like inside a function) but never actually used */
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-local-typedef"
#endif

#endif /* VMAWARE_PLATFORM_MACROS_H */

#if (VMAWARE_CPP >= 20)
    #include <bit>
#endif
#if (VMAWARE_CPP >= 17)
    #include <filesystem>
#endif
#ifdef VMAWARE_DEBUG
    #include <iomanip>
    #include <ios>
    #include <locale>
    #include <codecvt>
#endif
#include <limits>
#include <cstddef>
#include <system_error>
#include <ranges>
#include <cstdio>
#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <thread>
#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>
#include <sstream>
#include <bitset>
#include <type_traits>
#include <stdexcept>
#include <numeric>
#include <atomic>
#include <random>

#if (VMAWARE_WINDOWS)
    #include <windows.h>
    #include <winioctl.h>
    #include <winternl.h>
    #include <powerbase.h>
    #include <setupapi.h>
    #include <initguid.h>
    #include <devpkey.h>
    #include <devguid.h>
    #include <bcrypt.h>

    #pragma comment(lib, "setupapi.lib")
    #pragma comment(lib, "powrprof.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "gdi32.lib")
    #pragma comment(lib, "user32.lib")
#elif (VMAWARE_LINUX)
    #if (VMAWARE_X86)
        #include <cpuid.h>
        #include <x86intrin.h>
        #include <immintrin.h>
    #endif
    #include <sys/stat.h>
    #include <sys/statvfs.h>
    #include <sys/ioctl.h>
    #include <sys/syscall.h>
    #include <sys/sysinfo.h>
    #include <net/if.h> 
    #include <netinet/in.h>
    #include <unistd.h>
    #include <dirent.h>
    #include <memory>
    #include <cctype>
    #include <fcntl.h>
    #include <climits>
    #include <csignal>      
    #include <csetjmp>      
    #include <pthread.h>     
    #include <sched.h>      
    #include <cerrno>   
#elif (VMAWARE_APPLE)
    #if (VMAWARE_X86)
        #include <cpuid.h>
        #include <x86intrin.h>
        #include <immintrin.h>
    #endif
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <sys/user.h>
    #include <unistd.h>
    #include <time.h>
    #include <errno.h>
    #include <chrono>
#endif

#ifdef VMAWARE_DEBUG
    #define vma_debug(...) VM::util::debug_msg(__VA_ARGS__)
#else
    #define vma_debug(...)
#endif

#if (VMAWARE_WINDOWS)
    #if (VMAWARE_CLANG || VMAWARE_GCC)
        #define VMAWARE_SECTION __attribute__((section(".text")))
    #else
        #define VMAWARE_SECTION
    #endif

    #if (VMAWARE_MSVC)
        #pragma const_seg(".text")
    #endif

    #if (VMAWARE_X86)
        static const unsigned char vmload_stub[] VMAWARE_SECTION = { 0x0F, 0x01, 0xDA, 0xC3 };
        static const unsigned char vmcall_stub[] VMAWARE_SECTION = { 0x0F, 0x01, 0xC1, 0xC3 };
        static const unsigned char vmmcall_stub[] VMAWARE_SECTION = { 0x0F, 0x01, 0xD9, 0xC3 };
        static const unsigned char cpuid_blockstep_stub[] VMAWARE_SECTION = {
            0x53,                                      /* 0:  push rbx/ebx (preserve non-volatile register) */
            0x31, 0xC0,                                /* 1:  xor eax, eax */
            0x8C, 0xD0,                                /* 3:  mov ax, ss */
            0x9C,                                      /* 5:  pushfq/pushfd */
            0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,  /* 6:  or dword ptr [rsp/esp], 0x100 */
            0x9D,                                      /* 13: popfq/popfd */
            0x8E, 0xD0,                                /* 14: mov ss, ax  <- shadow starts here */
            0x0F, 0xA2,                                /* 16: cpuid       <- buggy hypervisor traps here */
            0x5B,                                      /* 18: pop rbx/ebx <- bare metal traps here */
            0x90,                                      /* 19: nop */
            0x9C,                                      /* 20: pushfq/pushfd */
            0x81, 0x24, 0x24, 0xFF, 0xFE, 0xFF, 0xFF,  /* 21: and dword ptr [rsp/esp], 0xFFFFFEFF */
            0x9D,                                      /* 28: popfq/popfd */
            0xC3                                       /* 29: ret */
        };
        static const unsigned char rdpru_blockstep_stub[] VMAWARE_SECTION = {
            0x53,                                      /* 0:  push rbx/ebx */
            0x31, 0xC9,                                /* 1:  xor ecx, ecx (set to MPERF to prevent #GP on bare metal) */
            0x31, 0xC0,                                /* 3:  xor eax, eax */
            0x8C, 0xD0,                                /* 5:  mov ax, ss */
            0x9C,                                      /* 7:  pushfq/pushfd */
            0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,  /* 8:  or dword ptr [rsp/esp], 0x100 */
            0x9D,                                      /* 15: popfq/popfd */
            0x8E, 0xD0,                                /* 16: mov ss, ax  <- shadow starts here */
            0x0F, 0x01, 0xFD,                          /* 18: rdpru       <- buggy hypervisor traps here */
            0x5B,                                      /* 21: pop rbx/ebx <- bare metal traps here (offset 21) */
            0x90,                                      /* 22: nop */
            0x9C,                                      /* 23: pushfq/pushfd */
            0x81, 0x24, 0x24, 0xFF, 0xFE, 0xFF, 0xFF,  /* 24: and dword ptr [rsp/esp], 0xFFFFFEFF */
            0x9D,                                      /* 31: popfq/popfd */
            0xC3                                       /* 32: ret */
        };
        static const unsigned char ud_stub[] VMAWARE_SECTION = { 0x0F, 0x0B, 0xC3 }; /* ud2; ret */

        #if (VMAWARE_X86_64)
            static const unsigned char cpuid_singlestep_stub[] VMAWARE_SECTION = {
                0x49, 0x89, 0xD8,                         /* mov r8, rbx */
                0x9C,                                     /* pushfq */
                0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, /* or dword ptr [rsp], 0x100 (sets TF) */
                0x9D,                                     /* popfq */
                0x0F, 0xA2,                               /* cpuid */
                0xC7, 0xB2,                               /* db 0xC7, 0xB2 (invalid opcode) */
                0xC3                                      /* ret */
            };
            static const unsigned char rdpru_singlestep_stub[] VMAWARE_SECTION = {
                0x49, 0x89, 0xD8,                         /* 0:  mov r8, rbx */
                0x31, 0xC9,                               /* 3:  xor ecx, ecx (set to MPERF register index 0 to avoid GP) */
                0x9C,                                     /* 5:  pushfq */
                0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, /* 6:  or dword ptr [rsp], 0x100 (sets TF) */
                0x9D,                                     /* 13: popfq */
                0x0F, 0x01, 0xFD,                         /* 14: rdpru */
                0xC7, 0xB2,                               /* 17: db 0xC7, 0xB2 (invalid opcode) */
                0xC3                                      /* 19: ret */
            };
            static const unsigned char trampoline_stub[] VMAWARE_SECTION = {
                0x49, 0x89, 0xD8,                         /* mov r8, rbx (save rbx to volatile register r8) */
                0x9C,                                     /* pushfq */
                0x81, 0x04, 0x24, 0x00, 0x01, 0x01, 0x00, /* or dword ptr [rsp], 0x10100 (set TF) */
                0x9D,                                     /* popfq */
                0x0F, 0xA2,                               /* cpuid */
                0x4C, 0x89, 0xC3,                         /* mov rbx, r8  (restore rbx from r8) - trap happens here */
                0xC3                                      /* ret */
            };
            static const unsigned char switch_stub[] VMAWARE_SECTION = {
                0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, /* push rbx, rbp, rdi, rsi, r12-r15 */
                0x49, 0x89, 0x20,                                                       /* qword ptr [r8], rsp */
                0x66, 0x8C, 0xD0,                                                       /* mov ax, ss */
                0x50,                                                                   /* push rax */
                0x52,                                                                   /* push rdx */
                0x9C,                                                                   /* pushfq */
                0x48, 0x8B, 0x41, 0x08,                                                 /* mov rax, qword ptr [rcx + 8] */
                0x50,                                                                   /* push rax */
                0x48, 0x8B, 0x01,                                                       /* mov rax, qword ptr [rcx] */
                0x50,                                                                   /* push rax */
                0x48, 0xCF                                                              /* iretq */
            };
            static const unsigned char dbvm_intel_stub[] VMAWARE_SECTION = {
                0x52,                                       /* push rdx */
                0x48, 0x89, 0xC8,                           /* mov rax, rcx */
                0x48, 0xBA, 0x10, 0x32, 0x54, 0x76, 0x00, 0x00, 0x00, 0x00, /* mov rdx, 0x76543210 */
                0x48, 0xB9, 0x90, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, /* mov rcx, 0x90909090 */
                0x0F, 0x01, 0xC1,                           /* vmcall */
                0x41, 0x5A,                                 /* pop r8 */
                0x49, 0x89, 0x00,                           /* mov [r8], rax */
                0xC3                                        /* ret */
            };
            static const unsigned char dbvm_amd_stub[] VMAWARE_SECTION = {
                0x52,                                       /* push rdx */
                0x48, 0x89, 0xC8,                           /* mov rax, rcx */
                0x48, 0xBA, 0x10, 0x32, 0x54, 0x76, 0x00, 0x00, 0x00, 0x00, /* mov rdx, 0x76543210 */
                0x48, 0xB9, 0x90, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, /* mov rcx, 0x90909090 */
                0x0F, 0x01, 0xD9,                           /* vmmcall */
                0x41, 0x5A,                                 /* pop r8 */
                0x49, 0x89, 0x00,                           /* mov [r8], rax */
                0xC3                                        /* ret */
            };
            static const unsigned char dbvm_icebp_stub[] VMAWARE_SECTION = {
                0xF1,                                           /* icebp */
                0xC3                                            /* ret */
            };
        #elif (VMAWARE_X86_32)
            static const unsigned char cpuid_singlestep_stub[] VMAWARE_SECTION = {
                0x89, 0xDF,                               /* mov edi, ebx */
                0x9C,                                     /* pushfd */
                0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, /* or dword ptr [esp], 0x100 (sets TF) */
                0x9D,                                     /* popfd */
                0x0F, 0xA2,                               /* cpuid */
                0xC7, 0xB2,                               /* db 0xC7, 0xB2 (invalid opcode) */
                0xC3                                      /* ret */
            };
            static const unsigned char rdpru_singlestep_stub[] VMAWARE_SECTION = {
                0x89, 0xDF,                               /* 0:  mov edi, ebx */
                0x31, 0xC9,                               /* 2:  xor ecx, ecx (set to MPERF register index 0 to avoid GP) */
                0x9C,                                     /* 4:  pushfd */
                0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, /* 5:  or dword ptr [esp], 0x100 (sets TF) */
                0x9D,                                     /* 12: popfd */
                0x0F, 0x01, 0xFD,                         /* 13: rdpru */
                0xC7, 0xB2,                               /* 16: db 0xC7, 0xB2 (invalid opcode) */
                0xC3                                      /* 18: ret */
            };
        #endif
    #elif (VMAWARE_ARM32)
        /* udf #0; bx lr, little-endian for 0xE7F000F0 and 0xE12FFF1E */
        static const unsigned char ud_stub[] VMAWARE_SECTION = { 0xF0, 0x00, 0xF0, 0xE7, 0x1E, 0xFF, 0x2F, 0xE1 };
    #elif (VMAWARE_ARM64)
        /* hlt #0; ret, little-endian for 0xD4400000 and 0xD65F03C0 */
        static const unsigned char ud_stub[] VMAWARE_SECTION = { 0x00, 0x00, 0x40, 0xD4, 0xC0, 0x03, 0x5F, 0xD6 };
    #endif

    #if (VMAWARE_MSVC)
        #pragma const_seg()
    #endif

    #if (VMAWARE_CLANG && !VMAWARE_MSVC)
        #if __has_declspec_attribute(guard)
            #define VMAWARE_NO_CFG __declspec(guard(nocf)) __attribute__((noinline))
        #elif __has_attribute(nocf_check)
            #define VMAWARE_NO_CFG __attribute__((nocf_check)) __attribute__((noinline))
        #else
            #define VMAWARE_NO_CFG __attribute__((noinline))
        #endif
    #elif (VMAWARE_GCC)
        #if defined(__has_attribute) && __has_attribute(nocf_check)
            #define VMAWARE_NO_CFG __attribute__((nocf_check)) __attribute__((noinline))
        #else
            #define VMAWARE_NO_CFG __attribute__((noinline))
        #endif
    #elif (VMAWARE_MSVC)
        #define VMAWARE_NO_CFG __declspec(guard(nocf)) __declspec(noinline)
    #else
        #define VMAWARE_NO_CFG
    #endif
#endif

struct VM {
private:
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i8  = std::int8_t;
    using i16 = std::int16_t;
    using i32 = std::int32_t;
    using i64 = std::int64_t;

public:
    enum enum_flags : u8 {
        /* Windows */
        GPU_CAPABILITIES = 0,
        ACPI_SIGNATURE,
        POWER_CAPABILITIES,
        DRIVERS,
        HANDLES,
        VIRTUAL_PROCESSORS,
        AUDIO,
        DISPLAY,
        DLL,
        WINE,
        VIRTUAL_REGISTRY,
        MUTEX,
        VPC_INVALID,
        VMWARE_STR,
        GAMARUE,
        CUCKOO,
        TRAP,
        UD,
        INTERRUPT_SHADOW,
        DBVM,
        KERNEL_OBJECTS,
        NVRAM,
        CPU_HEURISTIC,
        CLOCK,
        MSR,
        KVM_INTERCEPTION,
        HYPERVISOR_HOOK,
        SINGLE_STEP,
        EIP_OVERFLOW,
        SVM_EXCEPTIONS,
        MEASURED_BOOT,
        TPM, 

        /* Linux and Windows */
        SYSTEM_REGISTERS,
        FIRMWARE,
        DEVICES,
        AZURE,
        BOOT_LOGO,
        DISK,

        /* Linux */
        SMBIOS_VM_BIT,
        KMSG,
        CVENDOR,
        QEMU_FW_CFG,
        SYSTEMD,
        CTYPE,
        DOCKERENV,
        DMIDECODE,
        DMESG,
        HWMON,
        LINUX_USER_HOST,
        QEMU_VIRTUAL_DMI,
        QEMU_USB,
        HYPERVISOR_DIR,
        UML_CPU,
        VBOX_MODULE,
        SYSINFO_PROC,
        DMI_SCAN,
        PODMAN_FILE,
        WSL_PROC,
        FILE_ACCESS_HISTORY,
        MAC,
        CONTAINER_PID,
        BLUESTACKS_FOLDERS,
        AMD_SEV_MSR,
        TEMPERATURE,
        CGROUP,
        PROCESSES,

        /* Linux and MacOS */
        THREAD_COUNT,

        /* MacOS */
        MAC_MEMSIZE,
        MAC_IOKIT,
        MAC_SIP,
        IOREG_GREP,
        HWMODEL,
        MAC_SYS,

        /* Cross-platform */
        HYPERVISOR_BIT,
        VMID,
        THREAD_MISMATCH,
        TIMER,
        CPU_BRAND,
        HYPERVISOR_STR,
        CPUID_SIGNATURE,
        BOCHS_CPU,
        KGT_SIGNATURE,
        /*
         * ADD NEW TECHNIQUE ENUM NAME HERE
         *
         * special flags, different to settings
         */
        DEFAULT,
        ALL,
        NULL_ARG, /* Does nothing, just a placeholder flag mainly for the CLI */

        /* Start of settings technique flags (THE ORDERING IS VERY SPECIFIC HERE AND MIGHT BREAK SOMETHING IF RE-ORDERED) */
        HIGH_THRESHOLD,
        EXPERIMENTAL,
        DYNAMIC,
        MULTIPLE
    };

    enum class brand_enum : u8 {
        VBOX,
        VMWARE,
        VMWARE_EXPRESS,
        VMWARE_ESX,
        VMWARE_GSX,
        VMWARE_WORKSTATION,
        VMWARE_FUSION,
        VMWARE_HARD,
        BHYVE,
        KVM,
        QEMU,
        QEMU_KVM,
        KVM_HYPERV,
        QEMU_KVM_HYPERV,
        HYPERV,
        HYPERV_VPC,
        PARALLELS,
        XEN,
        ACRN,
        QNX,
        HYBRID,
        SANDBOXIE,
        DOCKER,
        WINE,
        VPC,
        ANUBIS,
        JOEBOX,
        THREATEXPERT,
        CWSANDBOX,
        COMODO,
        BOCHS,
        NVMM,
        BSD_VMM,
        INTEL_HAXM,
        UNISYS,
        LMHS,
        CUCKOO,
        BLUESTACKS,
        JAILHOUSE,
        APPLE_VZ,
        INTEL_KGT,
        AZURE_HYPERV,
        SIMPLEVISOR,
        HYPERV_ROOT,
        UML,
        POWERVM,
        GCE,
        OPENSTACK,
        KUBEVIRT,
        AWS_NITRO,
        PODMAN,
        WSL,
        OPENVZ,
        BAREVISOR,
        HYPERPLATFORM,
        MINIVISOR,
        INTEL_TDX,
        LKVM,
        AMD_SEV,
        AMD_SEV_ES,
        AMD_SEV_SNP,
        NEKO_PROJECT,
        NOIRVISOR,
        QIHOO,
        DBVM,
        UTM,
        COMPAQ,
        INSIGNIA,
        CONNECTIX,
        CONTAINERD,
        NULL_BRAND /* do not modify the placement for this, as it's used to count the number of brands here */
    };

    static constexpr u8 enum_size = MULTIPLE; /* Get enum size through value of last element */
    static constexpr u8 settings_count = static_cast<u8>(MULTIPLE - HIGH_THRESHOLD + 1); /* Get number of settings technique flags */
    static constexpr u16 base_technique_count = HIGH_THRESHOLD; /* Original technique count, constant on purpose (can also be used as a base count value if custom techniques are added) */
    static constexpr u16 threshold_score = 150; /* Standard threshold score */
    static constexpr u16 high_threshold_score = 300; /* New threshold score from 150 to 300 if VM::HIGH_THRESHOLD flag is enabled */
    static constexpr bool SHORTCUT = true; /* Macro for whether VM::core::run_all() should take a shortcut by skipping the rest of the techniques if the threshold score is already met */
    static constexpr size_t MAX_CUSTOM_TECHNIQUES = 256; /* Specific to VM::add_custom(), where custom techniques will be stored here */
    static constexpr size_t MAX_BRANDS = static_cast<size_t>(brand_enum::NULL_BRAND) + 1; /* VM scoreboard table specifically for VM::brand() */

    /* Intended for loop indexes */
    static constexpr u8 enum_begin = 0;
    static constexpr u8 enum_end = enum_size + 1;
    static constexpr u8 technique_begin = enum_begin;
    static constexpr u8 technique_end = DEFAULT;
    static constexpr u8 settings_begin = DEFAULT;
    static constexpr u8 settings_end = enum_end;

    /* For platform compatibility ranges */
    static constexpr u8 WINDOWS_START = VM::GPU_CAPABILITIES;
    static constexpr u8 WINDOWS_END = VM::DISK;
    static constexpr u8 LINUX_START = VM::SYSTEM_REGISTERS;
    static constexpr u8 LINUX_END = VM::THREAD_COUNT;
    static constexpr u8 MACOS_START = VM::THREAD_COUNT;
    static constexpr u8 MACOS_END = VM::MAC_SYS;

    /*
     * This is specifically meant for VM::detected_count() to
     * get the total number of techniques that detected a VM
     */
    static u8 detected_count_num;
    static u16 technique_count; /* get total number of techniques */

    static std::vector<enum_flags> disabled_techniques;
    static constexpr std::array<enum_flags, 1> experimental_techniques{ { FIRMWARE } };

#if (VMAWARE_WINDOWS)
    using brand_score_t = i32;
#else
    using brand_score_t = u8;
#endif

    /* For the flag bitset structure */
    using flagset = std::bitset<enum_size + 1>;

    /* Specific to brands */
    using brand_element_t = std::pair<brand_enum, brand_score_t>;
    using brand_list_t = std::vector<brand_element_t>;
    using brand_array_t = std::array<brand_element_t, MAX_BRANDS>;

    /* Constructor stuff */
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

    /* Compile-time checks */
    static_assert(std::is_integral<brand_score_t>::value, "brand_score_t must map to an integral type.");

    static_assert(enum_size == MULTIPLE, "enum_size must match the terminal element of the enum_flags.");
    static_assert(MAX_BRANDS == static_cast<size_t>(brand_enum::NULL_BRAND) + 1, "MAX_BRANDS must account for all elements including NULL_BRAND.");
    static_assert(enum_begin == 0, "enum_begin must start at 0.");
    static_assert(enum_end == enum_size + 1, "enum_end boundary calculation mismatch.");
    static_assert(technique_end == DEFAULT, "technique_end must match the transition point to settings flags.");
    static_assert(settings_begin == DEFAULT, "settings_begin must align with the transition point.");
    static_assert(settings_end == enum_end, "settings_end must align with the end of the flags.");

    static_assert(static_cast<u8>(brand_enum::NULL_BRAND) > 0, "brand_enum must contain at least one element.");
    static_assert(threshold_score > 0, "threshold_score must be a positive non-zero value.");
    static_assert(high_threshold_score >= threshold_score, "high_threshold_score cannot be less than base threshold.");
    static_assert(MAX_CUSTOM_TECHNIQUES > 0, "MAX_CUSTOM_TECHNIQUES must allow storage for at least one routine.");
    static_assert(WINDOWS_START < WINDOWS_END, "WINDOWS range bounds are logically inverted.");
    static_assert(LINUX_START < LINUX_END, "LINUX range bounds are logically inverted.");
    static_assert(MACOS_START < MACOS_END, "MACOS range bounds are logically inverted.");

    /* Specifically for util::hyper_x() and memo::hyperv */
    enum hyperx_state : u8 {
        HYPERV_UNKNOWN = 0,
        HYPERV_HOST,
        HYPERV_REAL_VM,
        HYPERV_NESTED_VM,
        HYPERV_ENLIGHTENMENT,
        HYPERV_SPOOFED
    };

    /* Various cpu operation stuff */
    struct cpu {
        /* cpuid leaf values */
        struct leaf {
            static constexpr u32
                basic_info = 0x00000000,
                features = 0x00000001,
                ext_features = 0x00000007,
                ext_topology = 0x0000000B,
                v2_ext_topology = 0x0000001F,
                hypervisor = 0x40000000,
                hv_interface = 0x40000001,
                hv_privileges = 0x40000003,
                hv_processors = 0x40000005,
                hv_nested = 0x40000006,
                hv_enlightenment = 0x40000100,
                func_ext = 0x80000000,
                proc_ext = 0x80000001,
                brand1 = 0x80000002,
                brand2 = 0x80000003,
                brand3 = 0x80000004,
                ext_limits = 0x80000008,
                encrypted_mem = 0x8000001F,
                amd_easter_egg = 0x8fffffff;
        };

        /* Internal helper using C++ references */
        static void cpuid_count(
            const u32 leaf,
            const u32 subleaf,
            u32& a,
            u32& b,
            u32& c,
            u32& d
        ) noexcept {
        #if (VMAWARE_X86)
            #if (VMAWARE_MSVC)
                int regs[4] = { 0 };
                __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
                a = static_cast<u32>(regs[0]);
                b = static_cast<u32>(regs[1]);
                c = static_cast<u32>(regs[2]);
                d = static_cast<u32>(regs[3]);
            #else
                __cpuid_count(leaf, subleaf, a, b, c, d);
            #endif  
        #else
            VMAWARE_UNUSED(leaf);
            VMAWARE_UNUSED(subleaf);
            VMAWARE_UNUSED(a);
            VMAWARE_UNUSED(b);
            VMAWARE_UNUSED(c);
            VMAWARE_UNUSED(d);
        #endif
        }

        /* Cross-platform wrapper for linux and MSVC cpuid */
        static void cpuid(u32& a, u32& b, u32& c, u32& d, const u32 a_leaf, const u32 c_leaf = 0xFF) noexcept {
        #if (VMAWARE_X86)
            /* May be unmodified for older 32-bit processors, clearing just in case */
            a = 0;
            b = 0;
            c = 0;
            d = 0;

            cpuid_count(a_leaf, c_leaf, a, b, c, d);
        #else
            VMAWARE_UNUSED(a);
            VMAWARE_UNUSED(b);
            VMAWARE_UNUSED(c);
            VMAWARE_UNUSED(d);
            VMAWARE_UNUSED(a_leaf);
            VMAWARE_UNUSED(c_leaf);
        #endif
        }

        /* Same as above but for array type parameters (MSVC specific) */
        static void cpuid(i32 x[4], const u32 a_leaf, const u32 c_leaf = 0xFF) noexcept {
        #if (VMAWARE_X86)
            /* May be unmodified for older 32-bit processors, clearing just in case */
            x[0] = 0;
            x[1] = 0;
            x[2] = 0;
            x[3] = 0;

            u32 a = 0u, b = 0u, c = 0u, d = 0u;
            cpuid_count(a_leaf, c_leaf, a, b, c, d);

            x[0] = static_cast<i32>(a);
            x[1] = static_cast<i32>(b);
            x[2] = static_cast<i32>(c);
            x[3] = static_cast<i32>(d);
        #else
            VMAWARE_UNUSED(x);
            VMAWARE_UNUSED(a_leaf);
            VMAWARE_UNUSED(c_leaf);
        #endif
        }

        [[nodiscard]] static bool is_leaf_supported(const u32 p_leaf) noexcept {
        #if (VMAWARE_APPLE) 
            return false;
        #endif
            bool cached = false;

            if (memo::leaf_cache::fetch(p_leaf, cached)) {
                return cached;
            }

            u32 eax = 0; 
            u32 unused = 0;
            bool supported = false;

            if (p_leaf < cpu::leaf::hypervisor) {
                /* Standard range: 0x00000000 - 0x3FFFFFFF */
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::basic_info);
                vma_debug("CPUID: max standard leaf = 0x", std::hex, eax);
                supported = (p_leaf <= eax);
            }
            else if (p_leaf < cpu::leaf::func_ext) {
                /* Hypervisor range: 0x40000000 - 0x7FFFFFFF */
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::hypervisor);
                vma_debug("CPUID: max hypervisor leaf = 0x", std::hex, eax);
                supported = (p_leaf <= eax);
            }
            else if (p_leaf < 0xC0000000) {
                /* Extended range: 0x80000000 - 0xBFFFFFFF */
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::func_ext);
                vma_debug("CPUID: max extended leaf = 0x", std::hex, eax);
                supported = (p_leaf <= eax);
            }
            else {
                supported = false;
            }

            memo::leaf_cache::store(p_leaf, supported);
            return supported;
        }

        [[nodiscard]] static bool is_amd() noexcept {
            constexpr u32 authentic_amd_ecx = 0x444d4163; /* "cAMD" */
            constexpr u32 amdisbetter_ecx = 0x21726574; /* "ter!" */

            u32 unused = 0;
            u32 ecx = 0;
            cpuid(unused, unused, ecx, unused, cpu::leaf::basic_info);

            return ecx == authentic_amd_ecx || ecx == amdisbetter_ecx;
        }

        [[nodiscard]] static bool is_intel() noexcept {
            constexpr u32 intel_ecx1 = 0x6c65746e; /* "ntel" */
            constexpr u32 intel_ecx2 = 0x6c65746f; /* "otel", this is because some Intel CPUs have a rare manufacturer string of "GenuineIotel" */

            u32 unused = 0;
            u32 ecx = 0;
            cpuid(unused, unused, ecx, unused, cpu::leaf::basic_info);

            return ((ecx == intel_ecx1) || (ecx == intel_ecx2));
        }

        [[nodiscard]] static const char* get_brand() noexcept {
            if (VMAWARE_LIKELY(memo::cpu_brand::is_cached())) {
                return memo::cpu_brand::fetch();
            }

        #if (!VMAWARE_X86 || VMAWARE_APPLE)
            return "Unknown";
        #else
            if (!cpu::is_leaf_supported(cpu::leaf::brand3)) {
                return "Unknown";
            }

            u32 regs[12] = { 0 };

            cpu::cpuid(regs[0], regs[1], regs[2], regs[3], cpu::leaf::brand1);
            cpu::cpuid(regs[4], regs[5], regs[6], regs[7], cpu::leaf::brand2);
            cpu::cpuid(regs[8], regs[9], regs[10], regs[11], cpu::leaf::brand3);

            static char buffer[49];
            std::memcpy(buffer, regs, sizeof(regs));
            buffer[48] = '\0';

            /*
             * Do NOT touch trailing spaces for the AMD_THREAD_MISMATCH technique
             *
             * left-trim only to handle stupid whitespaces before the brand string in ARM CPUs (Virtual CPUs)
             */
            const char* start_ptr = string::ltrim(buffer);

            memo::cpu_brand::store(start_ptr);
            vma_debug("CPU: ", start_ptr);

            /* Return pointer to the static cache, not the local stack buffer */
            return memo::cpu_brand::fetch();
        #endif
        }

        [[nodiscard]] static const char* cpu_manufacturer(const u32 leaf_id) {
            static const char* leaf_40000000 = nullptr;
            static const char* leaf_40000100 = nullptr;

            const char** cache = nullptr;

            switch (leaf_id) {
                case cpu::leaf::hypervisor:
                    cache = &leaf_40000000;
                    break;
                case cpu::leaf::hv_enlightenment:
                    cache = &leaf_40000100;
                    break;
                default:
                    /* VMAWARE_ASSUME(0); */
                    return "";
            }

            if (*cache) {
                return *cache;
            }

            u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, leaf_id);

            if (ebx == 0 && ecx == 0 && edx == 0) {
                *cache = "";
                return *cache;
            }

            static char buffers[2][13];

            const size_t index = (leaf_id == cpu::leaf::hypervisor) ? 0 : 1;

            u32 regs[3] = { ebx, ecx, edx };

            std::memcpy(buffers[index], regs, sizeof(regs));
            buffers[index][12] = '\0';

            *cache = buffers[index];
            return *cache;
        }

        struct stepping_struct {
            u8 model;
            u8 family;
            u8 extmodel;
        };

        static stepping_struct fetch_steppings() noexcept {
            struct stepping_struct steps {};

            u32 unused = 0;
            u32 eax = 0;

            cpu::cpuid(eax, unused, unused, unused, cpu::leaf::features);
            VMAWARE_UNUSED(unused);

            steps.model = ((eax >> 4) & 0b1111);
            steps.family = ((eax >> 8) & 0b1111);
            steps.extmodel = ((eax >> 16) & 0b1111);

            return steps;
        }

        /* Check if the CPU is an intel celeron */
        static bool is_celeron(const stepping_struct steps) noexcept {
            if (!cpu::is_intel()) {
                return false;
            }

            constexpr u8 celeron_model = 0xA;
            constexpr u8 celeron_family = 0x6;
            constexpr u8 celeron_extmodel = 0x2;

            return (
                steps.model == celeron_model &&
                steps.family == celeron_family &&
                steps.extmodel == celeron_extmodel
            );
        }

        struct model_struct {
            bool found;
            bool is_xeon;
            bool is_i_series;
            bool is_ryzen;
            const char* string;
        };

        [[nodiscard]] static model_struct get_model() noexcept {
            const char* brand = get_brand();

            model_struct result { false, false, false, false, {} };

            if (!brand) {
                return result;
            }

            if (cpu::is_intel()) {
                /* Ultra */
                if (string::find(brand, "Ultra") &&
                    strpbrk(brand, "0123456789")) {
                    result.found = true;
                    result.string = brand;
                    return result;
                }

                /* I-series */
                if (strchr(brand, 'i') &&
                    strchr(brand, '-') &&
                    strpbrk(brand, "0123456789")) {
                    result.found = true;
                    result.is_i_series = true;
                    result.string = brand;
                    return result;
                }

                /* Xeon */
                if (strpbrk(brand, "DEW") &&
                    strchr(brand, '-') &&
                    strpbrk(brand, "0123456789")) {
                    result.found = true;
                    result.is_xeon = true;
                    result.string = brand;
                    return result;
                }
            }
            else if (cpu::is_amd()) {
                if (string::find(brand, "AMD Ryzen")) {
                    result.found = true;
                    result.is_ryzen = true;
                    result.string = brand;
                    return result;
                }
            }

            return result;
        }

        [[nodiscard]] static bool vmid_template(const u32 p_leaf) {
            const std::string brand_str = cpu_manufacturer(p_leaf);

            if (brand_str == "Microsoft Hv") {
                /*
                 * A Hyper-V *host* (root partition) is not itself a guest VM, and a QEMU/KVM guest
                 * running with Hyper-V enlightenments is already attributed to QEMU_KVM_HYPERV by
                 * hyper_x(). In neither case should the "Microsoft Hv" vendor string be taken to
                 * mean the guest is genuine Microsoft Hyper-V.
                 */
                if (util::hyper_x() == HYPERV_HOST) {
                    return false;
                }
                return core::add(brand_enum::HYPERV);
            }

            if (util::find(brand_str, "KVM")) {
                return core::add(brand_enum::KVM);
            }

            static const std::unordered_map<std::string, enum brand_enum> brand_map = {
                {"VMwareVMware", brand_enum::VMWARE},
                {"VBoxVBoxVBox", brand_enum::VBOX},
                {"TCGTCGTCGTCG", brand_enum::QEMU},
                {"XenVMMXenVMM", brand_enum::XEN},
                {"Linux KVM Hv", brand_enum::KVM_HYPERV},
                {" prl hyperv ", brand_enum::PARALLELS},
                {" lrpepyh  vr", brand_enum::PARALLELS},
                {"bhyve bhyve ", brand_enum::BHYVE},
                {"BHyVE BHyVE ", brand_enum::BHYVE},
                {"ACRNACRNACRN", brand_enum::ACRN},
                {" QNXQVMBSQG ", brand_enum::QNX},
                {"___ NVMM ___", brand_enum::NVMM},
                {"OpenBSDVMM58", brand_enum::BSD_VMM},
                {"HAXMHAXMHAXM", brand_enum::INTEL_HAXM},
                {"UnisysSpar64", brand_enum::UNISYS},
                {"SRESRESRESRE", brand_enum::LMHS},
                {"Jailhouse\0\0\0", brand_enum::JAILHOUSE},
                {"EVMMEVMMEVMM", brand_enum::INTEL_KGT},
                {"Barevisor!\0\0", brand_enum::BAREVISOR},
                {"MiniVisor\0\0\0", brand_enum::MINIVISOR},
                {"IntelTDX    ", brand_enum::INTEL_TDX},
                {"LKVMLKVMLKVM", brand_enum::LKVM},
                {"Neko Project", brand_enum::NEKO_PROJECT},
                {"NoirVisor ZT", brand_enum::NOIRVISOR},
                {"Compaq FX!32", brand_enum::COMPAQ},
                {"Insignia 586", brand_enum::INSIGNIA},
                {"ConnectixCPU", brand_enum::CONNECTIX}
            };

            const auto it = brand_map.find(brand_str);
            if (it != brand_map.end()) {
                return core::add(it->second);
            }

            if (util::find(brand_str, "QXNQSBMV")) {
                return core::add(brand_enum::QNX);
            }

            if (util::find(brand_str, "Apple VZ")) {
                return core::add(brand_enum::APPLE_VZ);
            }

            if (util::find(brand_str, "PpyH")) {
                return core::add(brand_enum::HYPERPLATFORM);
            }

            return false;
        }

        struct constexpr_hash {
            /* 8 rounds of CRC32-C bit reflection recursively */
            static constexpr u32 crc32_bits(u32 crc, int bits) noexcept {
                return (bits == 0) ? crc :
                    crc32_bits((crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0), bits - 1);
            }

            /* Over string */
            static constexpr u32 crc32_str(const char* s, u32 crc) noexcept {
                return (*s == '\0') ? crc :
                    crc32_str(s + 1, crc32_bits(crc ^ static_cast<u8>(*s), 8));
            }

            static constexpr u32 get(const char* s) noexcept {
                return crc32_str(s, 0);
            }
        };

        /* This forces the compiler to calculate the hash when initializing the array while staying C++11 compatible */
        struct cpu_entry {
            u32 hash;
            u32 threads;
            bool smt;

            constexpr cpu_entry(const char* m, u32 t, bool s) noexcept
                : hash(constexpr_hash::get(m)), threads(t), smt(s) {
            }
        };

        enum class cpu_type : u8 {
            UNKNOWN,
            INTEL_I,
            INTEL_XEON,
            INTEL_ULTRA,
            AMD
        };

        static void get_intel_core_db(const cpu_entry*& out_ptr, size_t& out_size) noexcept {
            static constexpr cpu_entry db[] = {
                /* i3 series */
                { "i3-1000G1", 4, true },
                { "i3-1000G4", 4, true },
                { "i3-1000NG4", 4, true },
                { "i3-1005G1", 4, true },
                { "i3-10100", 8, true },
                { "i3-10100E", 8, true },
                { "i3-10100F", 8, true },
                { "i3-10100T", 8, true },
                { "i3-10100TE", 8, true },
                { "i3-10100Y", 4, true },
                { "i3-10105", 8, true },
                { "i3-10105F", 8, true },
                { "i3-10105T", 8, true },
                { "i3-10110U", 4, true },
                { "i3-10110Y", 4, true },
                { "i3-10300", 8, true },
                { "i3-10300T", 8, true },
                { "i3-10305", 8, true },
                { "i3-10305T", 8, true },
                { "i3-10320", 8, true },
                { "i3-10325", 8, true },
                { "i3-11100B", 8, true },
                { "i3-11100HE", 8, true },
                { "i3-1110G4", 4, true },
                { "i3-1115G4E", 4, true },
                { "i3-1115GRE", 4, true },
                { "i3-1120G4", 8, true },
                { "i3-12100", 8, true },
                { "i3-12100F", 8, true },
                { "i3-12100T", 8, true },
                { "i3-1210U", 8, true },
                { "i3-1215U", 8, true },
                { "i3-1215UE", 8, true },
                { "i3-1215UL", 8, true },
                { "i3-12300", 8, true },
                { "i3-12300T", 8, true },
                { "i3-13100", 8, true },
                { "i3-13100F", 8, true },
                { "i3-13100T", 8, true },
                { "i3-1315U", 8, true },
                { "i3-1315UE", 8, true },
                { "i3-14100", 8, true },
                { "i3-14100F", 8, true },
                { "i3-14100T", 8, true },
                { "i3-2100", 4, true },
                { "i3-2100T", 4, true },
                { "i3-2102", 4, true },
                { "i3-2105", 4, true },
                { "i3-2120", 4, true },
                { "i3-2120T", 4, true },
                { "i3-2125", 4, true },
                { "i3-2130", 4, true },
                { "i3-2308M", 4, true },
                { "i3-2310E", 4, true },
                { "i3-2310M", 4, true },
                { "i3-2312M", 4, true },
                { "i3-2328M", 4, true },
                { "i3-2330E", 4, true },
                { "i3-2330M", 4, true },
                { "i3-2332M", 4, true },
                { "i3-2340UE", 4, true },
                { "i3-2348M", 4, true },
                { "i3-2350LM", 4, true },
                { "i3-2350M", 4, true },
                { "i3-2355M", 4, true },
                { "i3-2357M", 4, true },
                { "i3-2365M", 4, true },
                { "i3-2367M", 4, true },
                { "i3-2370LM", 4, true },
                { "i3-2370M", 4, true },
                { "i3-2375M", 4, true },
                { "i3-2377M", 4, true },
                { "i3-2390M", 4, true },
                { "i3-2393M", 4, true },
                { "i3-2394M", 4, true },
                { "i3-2395M", 4, true },
                { "i3-2397M", 4, true },
                { "i3-3110M", 4, true },
                { "i3-3115C", 4, true },
                { "i3-3120M", 4, true },
                { "i3-3120ME", 4, true },
                { "i3-3130M", 4, true },
                { "i3-3210", 4, true },
                { "i3-3217U", 4, true },
                { "i3-3217UE", 4, true },
                { "i3-3220", 4, true },
                { "i3-3220T", 4, true },
                { "i3-3225", 4, true },
                { "i3-3227U", 4, true },
                { "i3-3229Y", 4, true },
                { "i3-3240", 4, true },
                { "i3-3240T", 4, true },
                { "i3-3245", 4, true },
                { "i3-3250", 4, true },
                { "i3-3250T", 4, true },
                { "i3-330E", 4, true },
                { "i3-330M", 4, true },
                { "i3-330UM", 4, true },
                { "i3-350M", 4, true },
                { "i3-370M", 4, true },
                { "i3-380M", 4, true },
                { "i3-380UM", 4, true },
                { "i3-390M", 4, true },
                { "i3-4000M", 4, true },
                { "i3-4005U", 4, true },
                { "i3-4010M", 4, true },
                { "i3-4010U", 4, true },
                { "i3-4010Y", 4, true },
                { "i3-4012Y", 4, true },
                { "i3-4020Y", 4, true },
                { "i3-4025U", 4, true },
                { "i3-4030U", 4, true },
                { "i3-4030Y", 4, true },
                { "i3-4100E", 4, true },
                { "i3-4100M", 4, true },
                { "i3-4100U", 4, true },
                { "i3-4102E", 4, true },
                { "i3-4110E", 4, true },
                { "i3-4110M", 4, true },
                { "i3-4112E", 4, true },
                { "i3-4120U", 4, true },
                { "i3-4130", 4, true },
                { "i3-4130T", 4, true },
                { "i3-4150", 4, true },
                { "i3-4150T", 4, true },
                { "i3-4158U", 4, true },
                { "i3-4160", 4, true },
                { "i3-4160T", 4, true },
                { "i3-4170", 4, true },
                { "i3-4170T", 4, true },
                { "i3-4330", 4, true },
                { "i3-4330T", 4, true },
                { "i3-4330TE", 4, true },
                { "i3-4340", 4, true },
                { "i3-4340TE", 4, true },
                { "i3-4350", 4, true },
                { "i3-4350T", 4, true },
                { "i3-4360", 4, true },
                { "i3-4360T", 4, true },
                { "i3-4370", 4, true },
                { "i3-4370T", 4, true },
                { "i3-5005U", 4, true },
                { "i3-5010U", 4, true },
                { "i3-5015U", 4, true },
                { "i3-5020U", 4, true },
                { "i3-5157U", 4, true },
                { "i3-530", 4, true },
                { "i3-540", 4, true },
                { "i3-550", 4, true },
                { "i3-560", 4, true },
                { "i3-6006U", 4, true },
                { "i3-6098P", 4, true },
                { "i3-6100", 4, true },
                { "i3-6100E", 4, true },
                { "i3-6100H", 4, true },
                { "i3-6100T", 4, true },
                { "i3-6100TE", 4, true },
                { "i3-6100U", 4, true },
                { "i3-6102E", 4, true },
                { "i3-6120T", 4, true },
                { "i3-6157U", 4, true },
                { "i3-6167U", 4, true },
                { "i3-6300", 4, true },
                { "i3-6300T", 4, true },
                { "i3-6320", 4, true },
                { "i3-6320T", 4, true },
                { "i3-7007U", 4, true },
                { "i3-7020U", 4, true },
                { "i3-7100", 4, true },
                { "i3-7100E", 4, true },
                { "i3-7100H", 4, true },
                { "i3-7100T", 4, true },
                { "i3-7100U", 4, true },
                { "i3-7101E", 4, true },
                { "i3-7101TE", 4, true },
                { "i3-7102E", 4, true },
                { "i3-7110U", 4, true },
                { "i3-7120", 4, true },
                { "i3-7120T", 4, true },
                { "i3-7130U", 4, true },
                { "i3-7167U", 4, true },
                { "i3-7300", 4, true },
                { "i3-7300T", 4, true },
                { "i3-7310T", 4, true },
                { "i3-7310U", 4, true },
                { "i3-7320", 4, true },
                { "i3-7320T", 4, true },
                { "i3-7340", 4, true },
                { "i3-7350K", 4, true },
                { "i3-8000", 4, false },
                { "i3-8000T", 4, false },
                { "i3-8020", 4, false },
                { "i3-8020T", 4, false },
                { "i3-8100", 4, false },
                { "i3-8100B", 4, false },
                { "i3-8100F", 4, false },
                { "i3-8100H", 4, false },
                { "i3-8100T", 4, false },
                { "i3-8109U", 4, true },
                { "i3-8120", 4, false },
                { "i3-8120T", 4, false },
                { "i3-8121U", 4, true },
                { "i3-8130U", 4, true },
                { "i3-8140U", 4, true },
                { "i3-8145U", 4, true },
                { "i3-8145UE", 4, true },
                { "i3-8300", 4, false },
                { "i3-8300T", 4, false },
                { "i3-8320", 4, false },
                { "i3-8320T", 4, false },
                { "i3-8350K", 4, false },
                { "i3-9100", 4, false },
                { "i3-9100E", 4, false },
                { "i3-9100F", 4, false },
                { "i3-9100HL", 4, false },
                { "i3-9100T", 4, false },
                { "i3-9100TE", 4, false },
                { "i3-9300", 4, false },
                { "i3-9300T", 4, false },
                { "i3-9320", 4, false },
                { "i3-9350K", 4, false },
                { "i3-9350KF", 4, false },
                { "i3-N300", 8, false },
                { "i3-N305", 8, false },
                { "i3-14100TE", 8, true },

                /* i5 series */
                { "i5-10200H", 8, true },
                { "i5-10210U", 8, true },
                { "i5-10210Y", 8, true },
                { "i5-10300H", 8, true },
                { "i5-1030G4", 8, true },
                { "i5-1030G7", 8, true },
                { "i5-1030NG7", 8, true },
                { "i5-10310U", 8, true },
                { "i5-10310Y", 8, true },
                { "i5-1035G1", 8, true },
                { "i5-1035G4", 8, true },
                { "i5-1035G7", 8, true },
                { "i5-1038NG7", 8, true },
                { "i5-10400", 12, true },
                { "i5-10400F", 12, true },
                { "i5-10400H", 8, true },
                { "i5-10400T", 12, true },
                { "i5-10500", 12, true },
                { "i5-10500E", 12, true },
                { "i5-10500H", 12, true },
                { "i5-10500T", 12, true },
                { "i5-10500TE", 12, true },
                { "i5-10505", 12, true },
                { "i5-10600", 12, true },
                { "i5-10600K", 12, true },
                { "i5-10600KF", 12, true },
                { "i5-10600T", 12, true },
                { "i5-1115G4", 4, true },
                { "i5-1125G4", 8, true },
                { "i5-11260H", 12, true },
                { "i5-11300H", 8, true },
                { "i5-1130G7", 8, true },
                { "i5-11320H", 8, true },
                { "i5-1135G7", 8, true },
                { "i5-11400", 12, true },
                { "i5-11400F", 12, true },
                { "i5-11400H", 12, true },
                { "i5-11400T", 12, true },
                { "i5-1140G7", 8, true },
                { "i5-1145G7", 8, true },
                { "i5-1145G7E", 8, true },
                { "i5-1145GRE", 8, true },
                { "i5-11500", 12, true },
                { "i5-11500B", 12, true },
                { "i5-11500H", 12, true },
                { "i5-11500HE", 12, true },
                { "i5-11500T", 12, true },
                { "i5-1155G7", 8, true },
                { "i5-11600", 12, true },
                { "i5-11600K", 12, true },
                { "i5-11600KF", 12, true },
                { "i5-11600T", 12, true },
                { "i5-1230U", 12, true },
                { "i5-1235U", 12, true },
                { "i5-12400", 12, true },
                { "i5-12400F", 12, true },
                { "i5-12400T", 12, true },
                { "i5-1240P", 16, true },
                { "i5-1240U", 12, true },
                { "i5-1245U", 12, true },
                { "i5-12490F", 12, true },
                { "i5-12500", 12, true },
                { "i5-12500H", 16, true },
                { "i5-12500HL", 16, true },
                { "i5-12500T", 12, true },
                { "i5-1250P", 16, true },
                { "i5-1250PE", 16, true },
                { "i5-12600", 12, true },
                { "i5-12600H", 16, true },
                { "i5-12600HE", 16, true },
                { "i5-12600HL", 16, true },
                { "i5-12600HX", 16, true },
                { "i5-12600K", 16, true },
                { "i5-12600KF", 16, true },
                { "i5-12600T", 12, true },
                { "i5-13400", 16, true },
                { "i5-13400F", 16, true },
                { "i5-13400T", 16, true },
                { "i5-1340P", 16, true },
                { "i5-1340PE", 16, true },
                { "i5-13490F", 16, true },
                { "i5-13500", 20, true },
                { "i5-13500H", 16, true },
                { "i5-13500T", 20, true },
                { "i5-13505H", 16, true },
                { "i5-1350P", 16, true },
                { "i5-1350PE", 16, true },
                { "i5-13600", 20, true },
                { "i5-13600H", 16, true },
                { "i5-13600HE", 16, true },
                { "i5-13600K", 20, true },
                { "i5-13600KF", 20, true },
                { "i5-13600T", 20, true },
                { "i5-2300", 4, false },
                { "i5-2310", 4, false },
                { "i5-2320", 4, false },
                { "i5-2380P", 4, false },
                { "i5-2390T", 4, true },
                { "i5-2400", 4, false },
                { "i5-2400S", 4, false },
                { "i5-2405S", 4, false },
                { "i5-2410M", 4, true },
                { "i5-2415M", 4, true },
                { "i5-2430M", 4, true },
                { "i5-2435M", 4, true },
                { "i5-2450M", 4, true },
                { "i5-2450P", 4, false },
                { "i5-2467M", 4, true },
                { "i5-2475M", 4, true },
                { "i5-2477M", 4, true },
                { "i5-2487M", 4, true },
                { "i5-2490M", 4, true },
                { "i5-2497M", 4, true },
                { "i5-2500", 4, false },
                { "i5-2500K", 4, false },
                { "i5-2500S", 4, false },
                { "i5-2500T", 4, false },
                { "i5-2510E", 4, true },
                { "i5-2515E", 4, true },
                { "i5-2520M", 4, true },
                { "i5-2537M", 4, true },
                { "i5-2540LM", 4, true },
                { "i5-2540M", 4, true },
                { "i5-2547M", 4, true },
                { "i5-2550K", 4, false },
                { "i5-2557M", 4, true },
                { "i5-2560LM", 4, true },
                { "i5-2560M", 4, true },
                { "i5-2580M", 4, true },
                { "i5-3210M", 4, true },
                { "i5-3230M", 4, true },
                { "i5-3317U", 4, true },
                { "i5-3320M", 4, true },
                { "i5-3330", 4, false },
                { "i5-3330S", 4, false },
                { "i5-3335S", 4, false },
                { "i5-3337U", 4, true },
                { "i5-3339Y", 4, true },
                { "i5-3340", 4, false },
                { "i5-3340M", 4, true },
                { "i5-3340S", 4, false },
                { "i5-3350P", 4, false },
                { "i5-3360M", 4, true },
                { "i5-3380M", 4, true },
                { "i5-3427U", 4, true },
                { "i5-3437U", 4, true },
                { "i5-3439Y", 4, true },
                { "i5-3450", 4, false },
                { "i5-3450S", 4, false },
                { "i5-3470", 4, false },
                { "i5-3470S", 4, false },
                { "i5-3470T", 4, true },
                { "i5-3475S", 4, false },
                { "i5-3550", 4, false },
                { "i5-3550S", 4, false },
                { "i5-3570", 4, false },
                { "i5-3570K", 4, false },
                { "i5-3570S", 4, false },
                { "i5-3570T", 4, false },
                { "i5-3610ME", 4, true },
                { "i5-4200H", 4, true },
                { "i5-4200M", 4, true },
                { "i5-4200U", 4, true },
                { "i5-4200Y", 4, true },
                { "i5-4202Y", 4, true },
                { "i5-4210H", 4, true },
                { "i5-4210M", 4, true },
                { "i5-4210U", 4, true },
                { "i5-4210Y", 4, true },
                { "i5-4220Y", 4, true },
                { "i5-4250U", 4, true },
                { "i5-4258U", 4, true },
                { "i5-4260U", 4, true },
                { "i5-4278U", 4, true },
                { "i5-4288U", 4, true },
                { "i5-4300M", 4, true },
                { "i5-4300U", 4, true },
                { "i5-4300Y", 4, true },
                { "i5-4302Y", 4, true },
                { "i5-4308U", 4, true },
                { "i5-430M", 4, true },
                { "i5-430UM", 4, true },
                { "i5-4310M", 4, true },
                { "i5-4310U", 4, true },
                { "i5-4330M", 4, true },
                { "i5-4340M", 4, true },
                { "i5-4350U", 4, true },
                { "i5-4360U", 4, true },
                { "i5-4400E", 4, true },
                { "i5-4402E", 4, true },
                { "i5-4402EC", 4, true },
                { "i5-4410E", 4, true },
                { "i5-4422E", 4, true },
                { "i5-4430", 4, false },
                { "i5-4430S", 4, false },
                { "i5-4440", 4, false },
                { "i5-4440S", 4, false },
                { "i5-4460", 4, false },
                { "i5-4460S", 4, false },
                { "i5-4460T", 4, false },
                { "i5-4470", 4, false },
                { "i5-450M", 4, true },
                { "i5-4570", 4, false },
                { "i5-4570R", 4, false },
                { "i5-4570S", 4, false },
                { "i5-4570T", 4, true },
                { "i5-4570TE", 4, true },
                { "i5-4590", 4, false },
                { "i5-4590S", 4, false },
                { "i5-4590T", 4, false },
                { "i5-460M", 4, true },
                { "i5-4670", 4, false },
                { "i5-4670K", 4, false },
                { "i5-4670R", 4, false },
                { "i5-4670S", 4, false },
                { "i5-4670T", 4, false },
                { "i5-4690", 4, false },
                { "i5-4690K", 4, false },
                { "i5-4690S", 4, false },
                { "i5-4690T", 4, false },
                { "i5-470UM", 4, true },
                { "i5-480M", 4, true },
                { "i5-5200U", 4, true },
                { "i5-520E", 4, true },
                { "i5-520M", 4, true },
                { "i5-520UM", 4, true },
                { "i5-5250U", 4, true },
                { "i5-5257U", 4, true },
                { "i5-5287U", 4, true },
                { "i5-5300U", 4, true },
                { "i5-5350H", 4, true },
                { "i5-5350U", 4, true },
                { "i5-540M", 4, true },
                { "i5-540UM", 4, true },
                { "i5-5575R", 4, false },
                { "i5-560M", 4, true },
                { "i5-560UM", 4, true },
                { "i5-5675C", 4, false },
                { "i5-5675R", 4, false },
                { "i5-580M", 4, true },
                { "i5-6198DU", 4, true },
                { "i5-6200U", 4, true },
                { "i5-6260U", 4, true },
                { "i5-6267U", 4, true },
                { "i5-6287U", 4, true },
                { "i5-6300HQ", 4, false },
                { "i5-6300U", 4, true },
                { "i5-6350HQ", 4, false },
                { "i5-6360U", 4, true },
                { "i5-6400", 4, false },
                { "i5-6400T", 4, false },
                { "i5-6402P", 4, false },
                { "i5-6440EQ", 4, false },
                { "i5-6440HQ", 4, false },
                { "i5-6442EQ", 4, false },
                { "i5-650", 4, true },
                { "i5-6500", 4, false },
                { "i5-6500T", 4, false },
                { "i5-6500TE", 4, false },
                { "i5-655K", 4, true },
                { "i5-6585R", 4, false },
                { "i5-660", 4, true },
                { "i5-6600", 4, false },
                { "i5-6600K", 4, false },
                { "i5-6600T", 4, false },
                { "i5-661", 4, true },
                { "i5-6685R", 4, false },
                { "i5-670", 4, true },
                { "i5-680", 4, true },
                { "i5-7200U", 4, true },
                { "i5-7210U", 4, true },
                { "i5-7260U", 4, true },
                { "i5-7267U", 4, true },
                { "i5-7287U", 4, true },
                { "i5-7300HQ", 4, false },
                { "i5-7300U", 4, true },
                { "i5-7360U", 4, true },
                { "i5-7400", 4, false },
                { "i5-7400T", 4, false },
                { "i5-7440EQ", 4, false },
                { "i5-7440HQ", 4, false },
                { "i5-7442EQ", 4, false },
                { "i5-750", 4, false },
                { "i5-7500", 4, false },
                { "i5-7500T", 4, false },
                { "i5-750S", 4, false },
                { "i5-760", 4, false },
                { "i5-7600", 4, false },
                { "i5-7600K", 4, false },
                { "i5-7600T", 4, false },
                { "i5-7640X", 4, false },
                { "i5-7Y54", 4, true },
                { "i5-7Y57", 4, true },
                { "i5-8200Y", 4, true },
                { "i5-8210Y", 4, true },
                { "i5-8250U", 8, true },
                { "i5-8257U", 8, true },
                { "i5-8259U", 8, true },
                { "i5-8260U", 8, true },
                { "i5-8265U", 8, true },
                { "i5-8269U", 8, true },
                { "i5-8279U", 8, true },
                { "i5-8300H", 8, true },
                { "i5-8305G", 8, true },
                { "i5-8310Y", 4, true },
                { "i5-8350U", 8, true },
                { "i5-8365U", 8, true },
                { "i5-8365UE", 8, true },
                { "i5-8400", 6, false },
                { "i5-8400B", 6, false },
                { "i5-8400H", 8, true },
                { "i5-8400T", 6, false },
                { "i5-8420", 6, false },
                { "i5-8420T", 6, false },
                { "i5-8500", 6, false },
                { "i5-8500B", 6, false },
                { "i5-8500T", 6, false },
                { "i5-8550", 6, false },
                { "i5-8600", 6, false },
                { "i5-8600K", 6, false },
                { "i5-8600T", 6, false },
                { "i5-8650", 6, false },
                { "i5-9300H", 8, true },
                { "i5-9300HF", 8, true },
                { "i5-9400", 6, false },
                { "i5-9400F", 6, false },
                { "i5-9400H", 8, true },
                { "i5-9400T", 6, false },
                { "i5-9500", 6, false },
                { "i5-9500E", 6, false },
                { "i5-9500F", 6, false },
                { "i5-9500T", 6, false },
                { "i5-9500TE", 6, false },
                { "i5-9600", 6, false },
                { "i5-9600K", 6, false },
                { "i5-9600KF", 6, false },
                { "i5-9600T", 6, false },
                { "i5-12450H", 12, true },
                { "i5-12450HX", 12, true },
                { "i5-12650H", 16, true },
                { "i5-13420H", 12, true },
                { "i5-13450HX", 16, true },
                { "i5-13500HX", 20, true },
                { "i5-13600HX", 20, true },
                { "i5-14400", 16, true },
                { "i5-14400F", 16, true },
                { "i5-14400T", 16, true },
                { "i5-14450HX", 16, true },
                { "i5-14490F", 16, true },
                { "i5-14500", 20, true },
                { "i5-14500GX", 20, true },
                { "i5-14500HX", 20, true },
                { "i5-14500T", 20, true },
                { "i5-14500TE", 20, true },
                { "i5-14600", 20, true },
                { "i5-14600K", 20, true },
                { "i5-14600KF", 20, true },
                { "i5-14600T", 20, true },
                { "i5-14501E", 12, true },
                { "i5-14501TE", 12, true },

                /* i7 series */
                { "i7-10510U", 8, true },
                { "i7-10510Y", 8, true },
                { "i7-1060G7", 8, true },
                { "i7-10610U", 8, true },
                { "i7-1065G7", 8, true },
                { "i7-1068G7", 8, true },
                { "i7-1068NG7", 8, true },
                { "i7-10700", 16, true },
                { "i7-10700E", 16, true },
                { "i7-10700F", 16, true },
                { "i7-10700K", 16, true },
                { "i7-10700KF", 16, true },
                { "i7-10700T", 16, true },
                { "i7-10700TE", 16, true },
                { "i7-10710U", 12, true },
                { "i7-10750H", 12, true },
                { "i7-10810U", 12, true },
                { "i7-10850H", 12, true },
                { "i7-10870H", 16, true },
                { "i7-10875H", 16, true },
                { "i7-11370H", 8, true },
                { "i7-11375H", 8, true },
                { "i7-11390H", 8, true },
                { "i7-11600H", 12, true },
                { "i7-1160G7", 8, true },
                { "i7-1165G7", 8, true },
                { "i7-11700", 16, true },
                { "i7-11700B", 16, true },
                { "i7-11700F", 16, true },
                { "i7-11700K", 16, true },
                { "i7-11700KF", 16, true },
                { "i7-11700T", 16, true },
                { "i7-11800H", 16, true },
                { "i7-1180G7", 8, true },
                { "i7-11850H", 16, true },
                { "i7-11850HE", 16, true },
                { "i7-1185G7", 8, true },
                { "i7-1185G7E", 8, true },
                { "i7-1185GRE", 8, true },
                { "i7-1195G7", 8, true },
                { "i7-1250U", 12, true },
                { "i7-1255U", 12, true },
                { "i7-1260P", 16, true },
                { "i7-1260U", 12, true },
                { "i7-1265U", 12, true },
                { "i7-12700", 20, true },
                { "i7-12700F", 20, true },
                { "i7-12700K", 20, true },
                { "i7-12700KF", 20, true },
                { "i7-12700T", 20, true },
                { "i7-12700H", 20, true },
                { "i7-1270P", 16, true },
                { "i7-1270PE", 16, true },
                { "i7-1360P", 16, true },
                { "i7-13700", 24, true },
                { "i7-13700F", 24, true },
                { "i7-13700K", 24, true },
                { "i7-13700KF", 24, true },
                { "i7-13700T", 24, true },
                { "i7-13790F", 24, true },
                { "i7-2535QM", 8, true },
                { "i7-2570QM", 8, true },
                { "i7-2600", 8, true },
                { "i7-2600K", 8, true },
                { "i7-2600S", 8, true },
                { "i7-2610UE", 4, true },
                { "i7-2617M", 4, true },
                { "i7-2620M", 4, true },
                { "i7-2627M", 4, true },
                { "i7-2629M", 4, true },
                { "i7-2630QM", 8, true },
                { "i7-2635QM", 8, true },
                { "i7-2637M", 4, true },
                { "i7-2640M", 4, true },
                { "i7-2649M", 4, true },
                { "i7-2655LE", 4, true },
                { "i7-2655QM", 8, true },
                { "i7-2657M", 4, true },
                { "i7-2660M", 4, true },
                { "i7-2667M", 4, true },
                { "i7-2669M", 4, true },
                { "i7-2670QM", 8, true },
                { "i7-2675QM", 8, true },
                { "i7-2677M", 4, true },
                { "i7-2685QM", 8, true },
                { "i7-2689M", 4, true },
                { "i7-2700K", 8, true },
                { "i7-2710QE", 8, true },
                { "i7-2715QE", 8, true },
                { "i7-2720QM", 8, true },
                { "i7-2740QM", 8, true },
                { "i7-2760QM", 8, true },
                { "i7-2820QM", 8, true },
                { "i7-2840QM", 8, true },
                { "i7-2860QM", 8, true },
                { "i7-2920XM", 8, true },
                { "i7-2960XM", 8, true },
                { "i7-3517U", 4, true },
                { "i7-3517UE", 4, true },
                { "i7-3520M", 4, true },
                { "i7-3537U", 4, true },
                { "i7-3540M", 4, true },
                { "i7-3555LE", 4, true },
                { "i7-3610QE", 8, true },
                { "i7-3610QM", 8, true },
                { "i7-3612QE", 8, true },
                { "i7-3612QM", 8, true },
                { "i7-3615QE", 8, true },
                { "i7-3615QM", 8, true },
                { "i7-3630QM", 8, true },
                { "i7-3632QM", 8, true },
                { "i7-3635QM", 8, true },
                { "i7-3667U", 4, true },
                { "i7-3687U", 4, true },
                { "i7-3689Y", 4, true },
                { "i7-3720QM", 8, true },
                { "i7-3740QM", 8, true },
                { "i7-3770", 8, true },
                { "i7-3770K", 8, true },
                { "i7-3770S", 8, true },
                { "i7-3770T", 8, true },
                { "i7-3820", 8, true },
                { "i7-3820QM", 8, true },
                { "i7-3840QM", 8, true },
                { "i7-3920XM", 8, true },
                { "i7-3930K", 12, true },
                { "i7-3940XM", 8, true },
                { "i7-3960X", 12, true },
                { "i7-3970X", 12, true },
                { "i7-4500U", 4, true },
                { "i7-4510U", 4, true },
                { "i7-4550U", 4, true },
                { "i7-4558U", 4, true },
                { "i7-4578U", 4, true },
                { "i7-4600M", 4, true },
                { "i7-4600U", 4, true },
                { "i7-4610M", 4, true },
                { "i7-4610Y", 4, true },
                { "i7-4650U", 4, true },
                { "i7-4700EC", 8, true },
                { "i7-4700EQ", 8, true },
                { "i7-4700HQ", 8, true },
                { "i7-4702EC", 8, true },
                { "i7-4700MQ", 8, true },
                { "i7-4701EQ", 8, true },
                { "i7-4702HQ", 8, true },
                { "i7-4702MQ", 8, true },
                { "i7-4710HQ", 8, true },
                { "i7-4710MQ", 8, true },
                { "i7-4712HQ", 8, true },
                { "i7-4712MQ", 8, true },
                { "i7-4720HQ", 8, true },
                { "i7-4722HQ", 8, true },
                { "i7-4750HQ", 8, true },
                { "i7-4760HQ", 8, true },
                { "i7-4765T", 8, true },
                { "i7-4770", 8, true },
                { "i7-4770HQ", 8, true },
                { "i7-4770K", 8, true },
                { "i7-4770R", 8, true },
                { "i7-4770S", 8, true },
                { "i7-4770T", 8, true },
                { "i7-4770TE", 8, true },
                { "i7-4771", 8, true },
                { "i7-4785T", 8, true },
                { "i7-4790", 8, true },
                { "i7-4790K", 8, true },
                { "i7-4790S", 8, true },
                { "i7-4790T", 8, true },
                { "i7-4800MQ", 8, true },
                { "i7-4810MQ", 8, true },
                { "i7-4820K", 8, true },
                { "i7-4850EQ", 8, true },
                { "i7-4850HQ", 8, true },
                { "i7-4860EQ", 8, true },
                { "i7-4860HQ", 8, true },
                { "i7-4870HQ", 8, true },
                { "i7-4900MQ", 8, true },
                { "i7-4910MQ", 8, true },
                { "i7-4930K", 12, true },
                { "i7-4930MX", 8, true },
                { "i7-4940MX", 8, true },
                { "i7-4950HQ", 8, true },
                { "i7-4960HQ", 8, true },
                { "i7-4960X", 12, true },
                { "i7-4980HQ", 8, true },
                { "i7-5500U", 4, true },
                { "i7-5550U", 4, true },
                { "i7-5557U", 4, true },
                { "i7-5600U", 4, true },
                { "i7-5650U", 4, true },
                { "i7-5700EQ", 8, true },
                { "i7-5700HQ", 8, true },
                { "i7-5750HQ", 8, true },
                { "i7-5775C", 8, true },
                { "i7-5775R", 8, true },
                { "i7-5820K", 12, true },
                { "i7-5850EQ", 8, true },
                { "i7-5850HQ", 8, true },
                { "i7-5930K", 12, true },
                { "i7-5950HQ", 8, true },
                { "i7-5960X", 16, true },
                { "i7-610E", 4, true },
                { "i7-620LE", 4, true },
                { "i7-620LM", 4, true },
                { "i7-620M", 4, true },
                { "i7-620UE", 4, true },
                { "i7-620UM", 4, true },
                { "i7-640LM", 4, true },
                { "i7-640M", 4, true },
                { "i7-640UM", 4, true },
                { "i7-6498DU", 4, true },
                { "i7-6500U", 4, true },
                { "i7-6560U", 4, true },
                { "i7-6567U", 4, true },
                { "i7-6600U", 4, true },
                { "i7-660LM", 4, true },
                { "i7-660UE", 4, true },
                { "i7-660UM", 4, true },
                { "i7-6650U", 4, true },
                { "i7-6660U", 4, true },
                { "i7-6700", 8, true },
                { "i7-6700HQ", 8, true },
                { "i7-6700K", 8, true },
                { "i7-6700T", 8, true },
                { "i7-6700TE", 8, true },
                { "i7-6770HQ", 8, true },
                { "i7-6785R", 8, true },
                { "i7-6800K", 12, true },
                { "i7-680UM", 4, true },
                { "i7-6820EQ", 8, true },
                { "i7-6820HK", 8, true },
                { "i7-6820HQ", 8, true },
                { "i7-6822EQ", 8, true },
                { "i7-6850K", 12, true },
                { "i7-6870HQ", 8, true },
                { "i7-6900K", 16, true },
                { "i7-6920HQ", 8, true },
                { "i7-6950X", 20, true },
                { "i7-6970HQ", 8, true },
                { "i7-720QM", 8, true },
                { "i7-740QM", 8, true },
                { "i7-7500U", 4, true },
                { "i7-7510U", 4, true },
                { "i7-7560U", 4, true },
                { "i7-7567U", 4, true },
                { "i7-7600U", 4, true },
                { "i7-7660U", 4, true },
                { "i7-7700", 8, true },
                { "i7-7700HQ", 8, true },
                { "i7-7700K", 8, true },
                { "i7-7700T", 8, true },
                { "i7-7740X", 8, true },
                { "i7-7800X", 12, true },
                { "i7-7820EQ", 8, true },
                { "i7-7820HK", 8, true },
                { "i7-7820HQ", 8, true },
                { "i7-7820X", 16, true },
                { "i7-7920HQ", 8, true },
                { "i7-7Y75", 4, true },
                { "i7-8086K", 12, true },
                { "i7-820QM", 8, true },
                { "i7-840QM", 8, true },
                { "i7-8500Y", 4, true },
                { "i7-8550U", 8, true },
                { "i7-8557U", 8, true },
                { "i7-8559U", 8, true },
                { "i7-8565U", 8, true },
                { "i7-8569U", 8, true },
                { "i7-860", 8, true },
                { "i7-860S", 8, true },
                { "i7-8650U", 8, true },
                { "i7-8665U", 8, true },
                { "i7-8665UE", 8, true },
                { "i7-8670", 12, true },
                { "i7-8670T", 12, true },
                { "i7-870", 8, true },
                { "i7-8700", 12, true },
                { "i7-8700B", 12, true },
                { "i7-8700K", 12, true },
                { "i7-8700T", 12, true },
                { "i7-8705G", 8, true },
                { "i7-8706G", 8, true },
                { "i7-8709G", 8, true },
                { "i7-870S", 8, true },
                { "i7-8750H", 12, true },
                { "i7-875K", 8, true },
                { "i7-880", 8, true },
                { "i7-8809G", 8, true },
                { "i7-8850H", 12, true },
                { "i7-920", 8, true },
                { "i7-920XM", 8, true },
                { "i7-930", 8, true },
                { "i7-940", 8, true },
                { "i7-940XM", 8, true },
                { "i7-950", 8, true },
                { "i7-960", 8, true },
                { "i7-965", 8, true },
                { "i7-970", 12, true },
                { "i7-9700", 8, false },
                { "i7-9700E", 8, false },
                { "i7-9700F", 8, false },
                { "i7-9700K", 8, false },
                { "i7-9700KF", 8, false },
                { "i7-9700T", 8, false },
                { "i7-9700TE", 8, false },
                { "i7-975", 8, true },
                { "i7-9750H", 12, true },
                { "i7-9750HF", 12, true },
                { "i7-980", 12, true },
                { "i7-9800X", 16, true },
                { "i7-980X", 12, true },
                { "i7-9850H", 12, true },
                { "i7-9850HE", 12, true },
                { "i7-9850HL", 12, true },
                { "i7-990X", 12, true },
                { "i7-12650H", 16, true },
                { "i7-12800H", 20, true },
                { "i7-12800HE", 20, true },
                { "i7-12800HX", 24, true },
                { "i7-12850HX", 24, true },
                { "i7-13620H", 16, true },
                { "i7-13650HX", 20, true },
                { "i7-13700H", 20, true },
                { "i7-13700HX", 24, true },
                { "i7-13705H", 20, true },
                { "i7-13800H", 20, true },
                { "i7-13850HX", 28, true },
                { "i7-14650HX", 24, true },
                { "i7-14700", 28, true },
                { "i7-14700F", 28, true },
                { "i7-14700H", 28, true },
                { "i7-14700HX", 28, true },
                { "i7-14700K", 28, true },
                { "i7-14700KF", 28, true },
                { "i7-14700T", 28, true },
                { "i7-14790F", 24, true },
                { "i7-14950HX", 24, true },
                { "i7-14700TE", 28, true },
                { "i7-14701E", 16, true },
                { "i7-14701TE", 16, true },

                /* i9 series */
                { "i9-7900X", 20, true },
                { "i9-7920X", 24, true },
                { "i9-7940X", 28, true },
                { "i9-7960X", 32, true },
                { "i9-7980XE", 36, true },
                { "i9-8950HK", 12, true },
                { "i9-9820X", 20, true },
                { "i9-9880H", 16, true },
                { "i9-9900", 16, true },
                { "i9-9900K", 16, true },
                { "i9-9900KF", 16, true },
                { "i9-9900KS", 16, true },
                { "i9-9900T", 16, true },
                { "i9-9900X", 20, true },
                { "i9-9920X", 24, true },
                { "i9-9940X", 28, true },
                { "i9-9960X", 32, true },
                { "i9-9980HK", 16, true },
                { "i9-9980XE", 36, true },
                { "i9-9990XE", 28, true },
                { "i9-10850K", 20, true },
                { "i9-10885H", 16, true },
                { "i9-10900", 20, true },
                { "i9-10900E", 20, true },
                { "i9-10900F", 20, true },
                { "i9-10900K", 20, true },
                { "i9-10900KF", 20, true },
                { "i9-10900T", 20, true },
                { "i9-10900TE", 20, true },
                { "i9-10900X", 20, true },
                { "i9-10910", 20, true },
                { "i9-10920X", 24, true },
                { "i9-10940X", 28, true },
                { "i9-10980HK", 16, true },
                { "i9-10980XE", 36, true },
                { "i9-11900", 16, true },
                { "i9-11900F", 16, true },
                { "i9-11900H", 16, true },
                { "i9-11900K", 16, true },
                { "i9-11900KB", 16, true },
                { "i9-11900KF", 16, true },
                { "i9-11900T", 16, true },
                { "i9-11950H", 16, true },
                { "i9-11980HK", 16, true },
                { "i9-12900", 24, true },
                { "i9-12900E", 24, true },
                { "i9-12900F", 24, true },
                { "i9-12900H", 20, true },
                { "i9-12900HK", 20, true },
                { "i9-12900HX", 24, true },
                { "i9-12900K", 24, true },
                { "i9-12900KF", 24, true },
                { "i9-12900KS", 24, true },
                { "i9-12900T", 24, true },
                { "i9-12900TE", 24, true },
                { "i9-12950HX", 24, true },
                { "i9-13900", 32, true },
                { "i9-13900E", 32, true },
                { "i9-13900F", 32, true },
                { "i9-13900H", 20, true },
                { "i9-13900HK", 20, true },
                { "i9-13900HX", 32, true },
                { "i9-13900K", 32, true },
                { "i9-13900KF", 32, true },
                { "i9-13900KS", 32, true },
                { "i9-13900T", 32, true },
                { "i9-13900TE", 32, true },
                { "i9-13905H", 20, true },
                { "i9-13950HX", 32, true },
                { "i9-13980HX", 32, true },
                { "i9-14900", 32, true },
                { "i9-14900F", 32, true },
                { "i9-14900HX", 32, true },
                { "i9-14900K", 32, true },
                { "i9-14900KF", 32, true },
                { "i9-14900KS", 32, true },
                { "i9-14900T", 32, true },
                { "i9-14901KE", 16, true },
                { "i9-14900TE", 32, true },
                { "i9-14901E", 16, true },
                { "i9-14901TE", 16, true }
            };

            static_assert(sizeof(db) / sizeof(cpu_entry) > 0, "Intel Core database must contain at least one entry.");
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }

        static void get_intel_xeon_db(const cpu_entry*& out_ptr, size_t& out_size) noexcept {
            static constexpr cpu_entry db[] = {
                { "D-1518", 8, true },
                { "D-1520", 8, true },
                { "D-1521", 8, true },
                { "D-1527", 8, true },
                { "D-1528", 12, true },
                { "D-1529", 8, true },
                { "D-1531", 12, true },
                { "D-1537", 16, true },
                { "D-1539", 16, true },
                { "D-1540", 16, true },
                { "D-1541", 16, true },
                { "D-1548", 16, true },
                { "D-1557", 24, true },
                { "D-1559", 24, true },
                { "D-1567", 24, true },
                { "D-1571", 32, true },
                { "D-1577", 32, true },
                { "D-1581", 32, true },
                { "D-1587", 32, true },
                { "D-1513N", 8, true },
                { "D-1523N", 8, true },
                { "D-1533N", 12, true },
                { "D-1543N", 16, true },
                { "D-1553N", 16, true },
                { "D-1602", 4, true },
                { "D-1612", 8, true },
                { "D-1622", 8, true },
                { "D-1627", 8, true },
                { "D-1632", 16, true },
                { "D-1637", 12, true },
                { "D-1623N", 8, true },
                { "D-1633N", 12, true },
                { "D-1649N", 16, true },
                { "D-1653N", 16, true },
                { "D-2141I", 16, true },
                { "D-2161I", 24, true },
                { "D-2191", 36, true },
                { "D-2123IT", 8, true },
                { "D-2142IT", 16, true },
                { "D-2143IT", 16, true },
                { "D-2163IT", 24, true },
                { "D-2173IT", 28, true },
                { "D-2183IT", 32, true },
                { "D-2145NT", 16, true },
                { "D-2146NT", 16, true },
                { "D-2166NT", 24, true },
                { "D-2177NT", 28, true },
                { "D-2187NT", 32, true },

                /* Xeon E */
                { "E-2104G", 4, false },
                { "E-2124", 4, false },
                { "E-2124G", 4, false },
                { "E-2126G", 6, false },
                { "E-2134", 8, true },
                { "E-2136", 12, true },
                { "E-2144G", 8, true },
                { "E-2146G", 12, true },
                { "E-2174G", 8, true },
                { "E-2176G", 12, true },
                { "E-2186G", 12, true },
                { "E-2176M", 12, true },
                { "E-2186M", 12, true },
                { "E-2224", 4, false },
                { "E-2224G", 4, false },
                { "E-2226G", 6, false },
                { "E-2234", 8, true },
                { "E-2236", 12, true },
                { "E-2244G", 8, true },
                { "E-2246G", 12, true },
                { "E-2274G", 8, true },
                { "E-2276G", 12, true },
                { "E-2278G", 16, true },
                { "E-2286G", 12, true },
                { "E-2288G", 16, true },
                { "E-2276M", 12, true },
                { "E-2286M", 16, true },
                { "E-2314", 4, false },
                { "E-2324G", 4, false },
                { "E-2334", 8, true },
                { "E-2336", 12, true },
                { "E-2356G", 12, true },
                { "E-2374G", 8, true },
                { "E-2378", 16, true },
                { "E-2378G", 16, true },
                { "E-2386G", 12, true },
                { "E-2388G", 16, true },
                { "E-2414", 4, false },
                { "E-2434", 8, true },
                { "E-2436", 12, true },
                { "E-2456", 12, true },
                { "E-2468", 16, true },
                { "E-2478", 16, true },
                { "E-2486", 12, true },
                { "E-2488", 16, true },

                /* Xeon W */
                { "W-2102", 4, false },
                { "W-2104", 4, false },
                { "W-2123", 8, true },
                { "W-2125", 8, true },
                { "W-2133", 12, true },
                { "W-2135", 12, true },
                { "W-2140B", 16, true },
                { "W-2145", 16, true },
                { "W-2150B", 20, true },
                { "W-2155", 20, true },
                { "W-2170B", 28, true },
                { "W-2175", 28, true },
                { "W-2191B", 36, true },
                { "W-2195", 36, true },
                { "W-3175X", 56, true },
                { "W-3223", 16, true },
                { "W-3225", 16, true },
                { "W-3235", 24, true },
                { "W-3245", 32, true },
                { "W-3245M", 32, true },
                { "W-3265", 48, true },
                { "W-3265M", 48, true },
                { "W-3275", 56, true },
                { "W-3275M", 56, true },
                { "w3-2423", 12, true },
                { "w3-2425", 12, true },
                { "w3-2435", 16, true },
                { "w5-2445", 20, true },
                { "w5-2455X", 24, true },
                { "w5-2465X", 32, true },
                { "w7-2475X", 40, true },
                { "w7-2495X", 48, true },
                { "w5-3425", 24, true },
                { "w5-3435X", 32, true },
                { "w7-3445", 40, true },
                { "w7-3455", 48, true },
                { "w7-3465X", 56, true },
                { "w9-3475X", 72, true },
                { "w9-3495X", 112, true },
                { "w3-2525", 16, true },
                { "w3-2535", 20, true },
                { "w5-2545", 24, true },
                { "w5-2555X", 28, true },
                { "w5-2565X", 36, true },
                { "w7-2575X", 44, true },
                { "w7-2595X", 52, true },
                { "w5-3525", 32, true },
                { "w5-3535X", 40, true },
                { "w7-3545", 48, true },
                { "w7-3555", 56, true },
                { "w7-3565X", 64, true },
                { "w9-3575X", 88, true },
                { "w9-3595X", 120, true }
            };

            static_assert(sizeof(db) / sizeof(cpu_entry) > 0, "Intel Xeon database must contain at least one entry.");
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }

        static void get_intel_ultra_db(const cpu_entry*& out_ptr, size_t& out_size) noexcept {
            static constexpr cpu_entry db[] = {
                /* Series 2 (Arrow Lake - Desktop/Mobile) */
                { "285K", 24, false },
                { "265K", 20, false },
                { "265KF", 20, false },
                { "245K", 14, false },
                { "245KF", 14, false },

                /* Series 2 (Arrow Lake-S Desktop Non-K and T) */
                { "285", 24, false },
                { "285T", 24, false },
                { "265", 20, false },
                { "265F", 20, false },
                { "265T", 20, false },
                { "245", 14, false },
                { "245T", 14, false },
                { "235", 14, false },
                { "235T", 14, false },
                { "225", 10, false },
                { "225F", 10, false },
                { "205", 8, false },

                /* Series 2 (Arrow Lake-S Desktop Plus) */
                { "270K Plus", 24, false },
                { "250K Plus", 18, false },
                { "250KF Plus", 18, false },

                /* Series 2 (Arrow Lake-HX Mobile) */
                { "285HX", 24, false },
                { "275HX", 24, false },
                { "265HX", 20, false },
                { "255HX", 20, false },
                { "245HX", 14, false },
                { "235HX", 14, false },

                /* Series 2 (Lunar Lake - Mobile) */
                { "288V", 8, false },
                { "268V", 8, false },
                { "258V", 8, false },
                { "266V", 8, false },
                { "256V", 8, false },
                { "238V", 8, false },
                { "236V", 8, false },
                { "228V", 8, false },
                { "226V", 8, false },

                /* Series 2 (Arrow Lake-HX Mobile Plus) */
                { "290HX Plus", 24, false },
                { "270HX Plus", 24, false },

                /* Series 2 (Arrow Lake-H Mobile) */
                { "285H", 16, false },
                { "265H", 16, false },
                { "255H", 16, false },
                { "235H", 14, false },
                { "225H", 14, false },

                /* Series 2 (Arrow Lake-U Mobile) */
                { "265U", 14, true },
                { "255U", 14, true },
                { "235U", 14, true },
                { "225U", 14, true },

                /* Series 2 (Arrow Lake-S Entry Level) */
                { "235A", 14, false },
                { "235TA", 14, false },
                { "235UA", 14, true },

                /*
                 * Series 1 (Meteor Lake - Mobile)
                 */
                { "185H", 22, true },
                { "165H", 22, true },
                { "155H", 22, true },
                { "135H", 18, true },
                { "125H", 18, true },
                { "165U", 14, true },
                { "155U", 14, true },
                { "150U", 12, true },
                { "135U", 14, true },
                { "125U", 14, true },
                { "120U", 12, true },
                { "100U", 8, true }
            };

            static_assert(sizeof(db) / sizeof(cpu_entry) > 0, "Intel Ultra database must contain at least one entry.");
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }

        static void get_amd_ryzen_db(const cpu_entry*& out_ptr, size_t& out_size) noexcept {
            static const cpu_entry db[] = {
                /* 3015/3020 */
                { "3015ce", 4, true },
                { "3015e", 4, true },
                { "3020e", 2, false },

                /* Athlon/Ax suffixes */
                { "860k", 4, false },
                { "870k", 4, false },
                { "pro-7350b", 4, false },
                { "pro-7800b", 4, false },
                { "pro-7850b", 4, false },
                { "a10-6700", 4, false },
                { "a10-6700t", 4, false },
                { "a10-6790b", 4, false },
                { "a10-6790k", 4, false },
                { "a10-6800b", 4, false },
                { "a10-6800k", 4, false },
                { "a10-7300", 4, false },
                { "a10-7400p", 4, false },
                { "a10-7700k", 4, false },
                { "a10-7800", 4, false },
                { "a10-7850k", 4, false },
                { "a10-7860k", 4, false },
                { "a10-7870k", 4, false },
                { "a10-8700b", 4, false },
                { "a10-8700p", 4, false },
                { "a10-8750b", 4, false },
                { "a10-8850b", 4, false },
                { "a12-8800b", 4, false },
                { "micro-6400t", 4, false },
                { "pro-3340b", 4, false },
                { "pro-3350b", 4, false },
                { "pro-7300b", 2, false },
                { "a4-5000", 4, false },
                { "a4-5100", 4, false },
                { "a4-6210", 4, false },
                { "a4-6300", 2, false },
                { "a4-6320", 2, false },
                { "a4-7210", 4, false },
                { "a4-7300", 2, false },
                { "a4-8350b", 2, false },
                { "a4-9120c", 2, false },
                { "pro-7050b", 2, false },
                { "pro-7400b", 2, false },
                { "a6-5200", 4, false },
                { "a6-5200m", 4, false },
                { "a6-5350m", 2, false },
                { "a6-6310", 4, false },
                { "a6-6400b", 2, false },
                { "a6-6400k", 2, false },
                { "a6-6420b", 2, false },
                { "a6-6420k", 2, false },
                { "a6-7000", 2, false },
                { "a6-7310", 4, false },
                { "a6-7400k", 2, false },
                { "a6-8500b", 2, false },
                { "a6-8500p", 2, false },
                { "a6-8550b", 2, false },
                { "a6-9220c", 2, false },
                { "pro-7150b", 4, false },
                { "pro-7600b", 4, false },
                { "a8-6410", 4, false },
                { "a8-6500", 4, false },
                { "a8-6500b", 4, false },
                { "a8-6500t", 4, false },
                { "a8-6600k", 4, false },
                { "a8-7100", 4, false },
                { "a8-7200p", 4, false },
                { "a8-7410", 4, false },
                { "a8-7600", 4, false },
                { "a8-7650k", 4, false },
                { "a8-7670k", 4, false },
                { "a8-8600b", 4, false },
                { "a8-8600p", 4, false },
                { "a8-8650b", 4, false },

                /* AI Series (Strix Point) */
                { "365", 20, true },
                { "370", 24, true }, 
                { "375", 24, true }, 
                { "350", 16, true },
                { "340", 12, true },

                /* Ryzen AI PRO 300 Series (Enterprise Strix/Krackan Point) */
                { "pro-340", 12, true },
                { "pro-350", 16, true },
                { "pro-360", 16, true },
                { "pro-365", 20, true },
                { "pro-370", 24, true },
                { "pro-375", 24, true },

                /* Athlon */
                { "3050c", 2, false },
                { "200ge", 4, true },
                { "220ge", 4, true },
                { "240ge", 4, true },
                { "255e", 2, false },
                { "3000g", 4, true },
                { "300ge", 4, true },
                { "300u", 4, true },
                { "320ge", 4, true },
                { "425e", 3, false },
                { "460", 3, false },
                { "5150", 4, false },
                { "5350", 4, false },
                { "5370", 4, false },
                { "620e", 4, false },
                { "631", 4, false },
                { "638", 4, false },
                { "641", 4, false },
                { "740", 4, false },
                { "750k", 4, false },
                { "760k", 4, false },
                { "3150c", 4, false },
                { "3150g", 4, false },
                { "3150ge", 4, false },
                { "3150u", 4, true },
                { "7220c", 4, true },
                { "7220u", 4, true },
                { "3045b", 2, false },
                { "3145b", 4, true },
                { "3050e", 4, true },
                { "3050ge", 4, true },
                { "3050u", 2, false },
                { "7120c", 2, false },
                { "7120u", 2, false },
                { "3125ge", 4, true },
                { "940", 4, false },
                { "950", 4, false },
                { "970", 4, false },

                /* Business Class */
                { "b57", 2, false },
                { "b59", 2, false },
                { "b60", 2, false },
                { "b75", 3, false },
                { "b77", 3, false },
                { "b97", 4, false },
                { "b99", 4, false },

                /* E-Series */
                { "micro-6200t", 2, false },
                { "e1-2100", 2, false },
                { "e1-2200", 2, false },
                { "e1-2500", 2, false },
                { "e1-6010", 2, false },
                { "e1-7010", 2, false },
                { "e2-3000", 2, false },
                { "e2-3800", 4, false },
                { "e2-6110", 4, false },
                { "e2-7110", 4, false },

                /* FX */
                { "fx-4100", 4, false },
                { "fx-4130", 4, false },
                { "fx-4170", 4, false },
                { "fx-4300", 4, false },
                { "fx-4320", 4, false },
                { "fx-4350", 4, false },
                { "fx-6200", 6, false },
                { "fx-6300", 6, false },
                { "fx-6350", 6, false },
                { "fx-7500", 4, false },
                { "fx-7600p", 4, false },
                { "fx-8120", 8, false },
                { "fx-8150", 8, false },
                { "fx-8300", 8, false },
                { "fx-8310", 8, false },
                { "fx-8320", 8, false },
                { "fx-8320e", 8, false },
                { "fx-8350", 8, false },
                { "fx-8370", 8, false },
                { "fx-8370e", 8, false },
                { "fx-8800p", 4, false },
                { "fx-9370", 8, false },
                { "fx-9590", 8, false },

                /* Misc */
                { "micro-6700t", 4, false },
                { "n640", 2, false },
                { "n660", 2, false },
                { "n870", 3, false },
                { "n960", 4, false },
                { "n970", 4, false },
                { "p650", 2, false },
                { "p860", 3, false },

                /* Phenom II */
                { "1075t", 6, false },
                { "555", 2, false },
                { "565", 2, false },
                { "570", 2, false },
                { "840", 4, false },
                { "850", 4, false },
                { "960t", 4, false },
                { "965", 4, false },
                { "975", 4, false },
                { "980", 4, false },

                /* Ryzen Suffixes (3/5/7/9/Threadripper consolidated) */
                { "1200", 4, false },
                { "1300x", 4, false },
                /* "210" mapped to Ryzen 5 1400 (First Gen 4c/8t) */
                { "210", 8, true },
                { "2200g", 4, false },
                { "2200ge", 4, false },
                { "2200u", 4, true },
                { "2300u", 4, false },
                { "2300x", 4, false },
                { "3100", 8, true },
                { "3200g", 4, false },
                { "3200ge", 4, false },
                { "3200u", 4, true },
                { "3250c", 4, true },
                { "3250u", 4, true },
                { "3300u", 4, false },
                { "3300x", 8, true },
                { "3350u", 4, false },
                { "4100", 8, true },
                { "4300g", 8, true },
                { "4300ge", 8, true },
                { "4300u", 4, false },
                { "5125c", 4, true },
                { "5300g", 8, true },
                { "5300ge", 8, true },
                { "5300u", 8, true },
                { "5305g", 8, true },
                { "5305ge", 8, true },
                { "5400u", 8, true },
                { "5425c", 8, true },
                { "5425u", 8, true },
                { "7320c", 8, true },
                { "7320u", 8, true },
                { "7330u", 8, true },
                { "7335u", 8, true },
                { "7440u", 8, true },
                { "8300g", 8, true },
                { "8300ge", 8, true },
                { "8440u", 8, true },
                { "1300", 4, false },
                { "4350g", 8, true },
                { "4350ge", 8, true },
                { "4355g", 8, true },
                { "4355ge", 8, true },
                { "4450u", 8, true },
                { "5350g", 8, true },
                { "5350ge", 8, true },
                { "5355g", 8, true },
                { "5355ge", 8, true },
                { "5450u", 8, true },
                { "5475u", 8, true },
                { "1400", 8, true },
                { "1500x", 8, true },
                { "1600", 12, true },
                { "1600x", 12, true },
                /* "220" mapped to Ryzen 5 1600 (First Gen 6c/12t) */
                { "220", 12, true },
                /* "230" mapped to Ryzen 5 2600 (Second Gen 6c/12t) */
                { "230", 12, true },
                /* "240" mapped to Ryzen 5 3600 (Third Gen 6c/12t) */
                { "240", 12, true },
                { "2400g", 8, true },
                { "2400ge", 8, true },
                { "2500u", 8, true },
                { "2500x", 8, true },
                { "2600", 12, true },
                { "2600e", 12, true },
                { "2600h", 8, true },
                { "2600x", 12, true },
                { "3400g", 8, true },
                { "3400ge", 8, true },
                { "3450u", 8, true },
                { "3500", 6, false },
                { "3500c", 8, true },
                { "3500u", 8, true },
                { "3550h", 8, true },
                { "3580u", 8, true },
                { "3600", 12, true },
                { "3600x", 12, true },
                { "3600xt", 12, true },
                { "4500", 12, true },
                { "4500u", 6, false },
                { "4600g", 12, true },
                { "4600ge", 12, true },
                { "4600h", 12, true },
                { "4600u", 12, true },
                { "4680u", 12, true },
                { "5500", 12, true },
                { "5500gt", 12, true },
                { "5500h", 8, true },
                { "5500u", 12, true },
                { "5560u", 12, true },
                { "5600", 12, true },
                { "5600g", 12, true },
                { "5600ge", 12, true },
                { "5600gt", 12, true },
                { "5600h", 12, true },
                { "5600hs", 12, true },
                { "5600t", 12, true },
                { "5600u", 12, true },
                { "5600x", 12, true },
                { "5600x3d", 12, true },
                { "5600xt", 12, true },
                { "5605g", 12, true },
                { "5605ge", 12, true },
                { "5625c", 12, true },
                { "5625u", 12, true },
                { "6600h", 12, true },
                { "6600hs", 12, true },
                { "6600u", 12, true },
                { "7235hs", 8, true },
                { "7400f", 12, true },
                { "7430u", 12, true },
                { "7500f", 12, true },
                { "7520c", 8, true },
                { "7520u", 8, true },
                { "7530u", 12, true },
                { "7535hs", 12, true },
                { "7535u", 12, true },
                { "7540u", 12, true },
                { "7545u", 12, true },
                { "7600", 12, true },
                { "7600x", 12, true },
                { "7600x3d", 12, true },
                { "7640hs", 12, true },
                { "7640u", 12, true },
                { "7645hx", 12, true },
                { "8400f", 12, true },
                { "8500g", 12, true }, /* Zen 4 base with SMT */
                { "8500ge", 12, true },
                { "8540u", 12, true },
                { "8600g", 12, true },
                { "8640hs", 12, true },
                { "8640u", 12, true },
                { "8645hs", 12, true },
                { "9600", 12, true },
                { "9600x", 12, true },
                { "1500", 8, true },
                { "3350g", 8, true },
                { "3350ge", 8, true },
                { "4650g", 12, true },
                { "4650ge", 12, true },
                { "4650u", 12, true },
                { "4655g", 12, true },
                { "4655ge", 12, true },
                { "5645", 12, true },
                { "5650g", 12, true },
                { "5650ge", 12, true },
                { "5650u", 12, true },
                { "5655g", 12, true },
                { "5655ge", 12, true },
                { "5675u", 12, true },
                { "6650h", 12, true },
                { "6650hs", 12, true },
                { "6650u", 12, true },
                { "1700", 16, true },
                { "1700x", 16, true },
                { "1800x", 16, true },
                /* "250" mapped to Ryzen 7 1700 (First Gen 8c/16t) */
                { "250", 16, true },
                /* "260" mapped to Ryzen 7 2700 (Second Gen 8c/16t) */
                { "260", 16, true },
                { "2700", 16, true },
                { "2700e", 16, true },
                { "2700u", 8, true },
                { "2700x", 16, true },
                { "2800h", 8, true },
                { "3700c", 8, true },
                { "3700u", 8, true },
                { "3700x", 16, true },
                { "3750h", 8, true },
                { "3780u", 8, true },
                { "3800x", 16, true },
                { "3800xt", 16, true },
                { "4700g", 16, true },
                { "4700ge", 16, true },
                { "4700u", 8, false },
                { "4800h", 16, true },
                { "4800hs", 16, true },
                { "4800u", 16, true },
                { "4980u", 16, true },
                { "5700", 16, true },
                { "5700g", 16, true },
                { "5700ge", 16, true },
                { "5700u", 16, true },
                { "5700x", 16, true },
                { "5700x3d", 16, true },
                { "5705g", 16, true },
                { "5705ge", 16, true },
                { "5800", 16, true },
                { "5800h", 16, true },
                { "5800hs", 16, true },
                { "5800u", 16, true },
                { "5800x", 16, true },
                { "5800x3d", 16, true },
                { "5800xt", 16, true },
                { "5825c", 16, true },
                { "5825u", 16, true },
                { "6800h", 16, true },
                { "6800hs", 16, true },
                { "6800u", 16, true },
                { "7435hs", 16, true },
                { "7700", 16, true },
                { "7700x", 16, true },
                { "7730u", 16, true },
                { "7735hs", 16, true },
                { "7735u", 16, true },
                { "7736u", 16, true },
                { "7745hx", 16, true },
                { "7800x3d", 16, true },
                { "7840hs", 16, true },
                { "7840hx", 24, true },
                { "7840u", 16, true },
                { "8700f", 16, true },
                { "8700g", 16, true },
                { "8840hs", 16, true },
                { "8840u", 16, true },
                { "8845hs", 16, true },
                { "9700x", 16, true },
                { "9800x3d", 16, true },
                { "4750g", 16, true },
                { "4750ge", 16, true },
                { "4750u", 16, true },
                { "5750g", 16, true },
                { "5750ge", 16, true },
                { "5755g", 16, true },
                { "5755ge", 16, true },
                { "5845", 16, true },
                { "5850u", 16, true },
                { "5875u", 16, true },
                { "6850h", 16, true },
                { "6850hs", 16, true },
                { "6850u", 16, true },
                { "6860z", 16, true },
                { "7745", 16, true },
                /* "270" mapped to Ryzen 7 3700X (Third Gen 8c/16t) */
                { "270", 16, true },
                { "3900", 24, true },
                { "3900x", 24, true },
                { "3900xt", 24, true },
                { "3950x", 32, true },
                { "4900h", 16, true },
                { "4900hs", 16, true },
                { "5900", 24, true },
                { "5900hs", 16, true },
                { "5900hx", 16, true },
                { "5900x", 24, true },
                { "5900xt", 32, true },
                { "5950x", 32, true },
                { "5980hs", 16, true },
                { "5980hx", 16, true },
                { "6900hs", 16, true },
                { "6900hx", 16, true },
                { "6980hs", 16, true },
                { "6980hx", 16, true },
                { "7845hx", 24, true },
                { "7900", 24, true },
                { "7900x", 24, true },
                { "7900x3d", 24, true },
                { "7940hs", 16, true },
                { "7940hx", 32, true },
                { "7945hx", 32, true },
                { "7945hx3d", 32, true },
                { "7950x", 32, true },
                { "7950x3d", 32, true },
                { "8945hs", 16, true },
                { "9850hx", 24, true },
                { "9900x", 24, true },
                { "9900x3d", 24, true },
                { "9950x", 32, true },
                { "9950x3d", 32, true },
                { "9955hx", 32, true },
                { "9600x3d", 12, true },
                { "5945", 24, true },
                { "6950h", 16, true },
                { "6950hs", 16, true },
                { "7945", 24, true },
                { "1900x", 16, true },
                { "1920x", 24, true },
                { "1950x", 32, true },
                { "2920x", 24, true },
                { "2950x", 32, true },
                { "2970wx", 48, true },
                { "2990wx", 64, true },
                { "3960x", 48, true },
                { "3970x", 64, true },
                { "3990x", 128, true },
                { "7960x", 48, true },
                { "7970x", 64, true },
                { "7980x", 128, true },
                { "3945wx", 24, true },
                { "3955wx", 32, true },
                { "3975wx", 64, true },
                { "3995wx", 128, true },
                { "5945wx", 24, true },
                { "5955wx", 32, true },
                { "5965wx", 48, true },
                { "5975wx", 64, true },
                { "5995wx", 128, true },
                { "7945wx", 24, true },
                { "7955wx", 32, true },
                { "7965wx", 48, true },
                { "7975wx", 64, true },
                { "7985wx", 128, true },
                { "7995wx", 192, true },

                /* Sempron */
                { "2650", 2, false },
                { "3850", 4, false },

                /* Z-Series */
                { "z1", 12, true }
            };

            static_assert(sizeof(db) / sizeof(cpu_entry) > 0, "AMD Ryzen database must contain at least one entry.");
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }
    };

    template <std::size_t N>
    static inline void str_copy(char(&dest)[N], const char* VMAWARE_RESTRICT src) noexcept {
        static_assert(N > 0, "Destination buffer must have non-zero size");

        if (!src) {
            dest[0] = '\0';
            return;
        }

        const char* const end = static_cast<const char*>(std::memchr(src, '\0', N));
        const std::size_t copy_len = end ? static_cast<std::size_t>(end - src) : (N - 1);

        std::memcpy(dest, src, copy_len);
        dest[copy_len] = '\0';
    }

    /* Memoization */
    struct memo {
        struct data_t {
            bool result;
            u8 points;
            bool cached;
            brand_enum brand_name;
        };
        struct cache_entry {
            bool result;
            u8 points;
            bool has_value;
            brand_enum brand_name;
        };

        static std::array<cache_entry, enum_size + 1> cache_table;

        static VMAWARE_CONSTEXPR void cache_store(u16 flag, bool result, u8 points, const brand_enum brand = brand_enum::NULL_BRAND) noexcept {
            if (flag <= enum_size) {
                VMAWARE_ASSUME(flag <= enum_size);
                cache_table[flag] = { result, points, true, brand };
            }
        }

        static constexpr bool is_cached(u16 flag) noexcept {
            return VMAWARE_LIKELY(flag <= enum_size) && cache_table[flag].has_value;
        }

        static VMAWARE_CONSTEXPR data_t cache_fetch(u16 flag) noexcept {
            if (VMAWARE_UNLIKELY(flag > enum_size)) {
                return { false, 0, false, brand_enum::NULL_BRAND };
            }

            if (VMAWARE_LIKELY(cache_table[flag].has_value)) {
                const auto& entry = cache_table[flag];
                return { entry.result, entry.points, true, entry.brand_name };
            }

            return { false, 0, false, brand_enum::NULL_BRAND };
            return { false, 0, false, brand_enum::NULL_BRAND };
        }

        struct single_brand {
            static brand_enum brand_cache;
            static flagset cached_flags;
            static bool cached;

            static void store(const brand_enum s, const flagset& flags) noexcept {
                brand_cache = s;
                cached_flags = flags;
                cached = true;
            }

            static bool is_cached(const flagset& flags) noexcept {
                return cached && (cached_flags == flags); 
            }
            
            static brand_enum fetch() noexcept {
                return brand_cache; 
            }
        };

        struct multi_brand {
            static std::string brand_cache;
            static flagset cached_flags;
            static bool cached;

            static void store(const std::string& s, const flagset& flags) noexcept {
                brand_cache = s;
                cached_flags = flags;
                cached = true;
            }

            static bool is_cached(const flagset& flags) noexcept {
                return cached && (cached_flags == flags);
            }

            static std::string fetch() noexcept {
                return brand_cache;
            }
        };

        struct brand_list {
            static brand_list_t cache;
            static flagset cached_flags;
            static bool cached;

            static void store(const brand_list_t& list, const flagset& flags) noexcept {
                cache = list;
                cached_flags = flags;
                cached = true;
            }

            static bool is_cached(const flagset& flags) noexcept {
                return cached && (cached_flags == flags);
            }

            static brand_list_t fetch() noexcept {
                return cache;
            }
        };

        /* Helper specifically for conclusion strings */
        struct conclusion {
            static char cache[512];
            static flagset cached_flags;
            static bool cached;

            static void store(const char* s, const flagset& flags) noexcept {
                str_copy(cache, s);
                cached_flags = flags;
                cached = true;
            }

            static bool is_cached(const flagset& flags) noexcept {
                return cached && (cached_flags == flags);
            }

            static const char* fetch() noexcept {
                return cache; 
            }
        };

        struct cpu_brand {
            static char brand_cache[128];
            static bool cached;

            static void store(const char* s) noexcept {
                str_copy(brand_cache, s); 
                cached = true;
            }

            static bool is_cached() noexcept {
                return cached; 
            }

            static const char* fetch() noexcept {
                return brand_cache; 
            }
        };

        struct thread_count {
            static u32 thread_count_cache;

            static u32 fetch() noexcept {
                if (VMAWARE_LIKELY(thread_count_cache != 0)) {
                    VMAWARE_ASSUME(thread_count_cache != 0);
                    return thread_count_cache;
                }
                thread_count_cache = std::thread::hardware_concurrency();
                return thread_count_cache;
            }
        };

        struct hyperx {
            static hyperx_state state;
            static bool cached;

            static hyperx_state fetch() noexcept {
                return state; 
            }

            static void store(const hyperx_state p_state) noexcept {
                state = p_state;
                cached = true;
            }

            static bool is_cached() noexcept {
                return cached;
            }
        };

        struct leaf_entry { 
            u32 leaf; 
            bool value;
            bool has_value; 
        };

        struct leaf_cache {
            static constexpr std::size_t CAPACITY = 128;
            static std::array<leaf_entry, CAPACITY> table;
            static std::size_t count;      
            static std::size_t next_index; 

            static bool fetch(u32 leaf, bool& out) noexcept {
                for (std::size_t i = 0; i < count; ++i) {
                    if (table[i].has_value && table[i].leaf == leaf) {
                        out = table[i].value;
                        return true;
                    }
                }

                return false;
            }

            static void store(u32 leaf, bool val) noexcept {
                for (std::size_t i = 0; i < count; ++i) {
                    auto& entry = table[i];
                    if (entry.leaf == leaf) {
                        entry.value = val;
                        entry.has_value = true;
                        return;
                    }
                }

                if (count < CAPACITY) {
                    table[count++] = { leaf, val, true };
                    return;
                }

                table[next_index] = { leaf, val, true };
                next_index = (next_index + 1) % CAPACITY;
            }
        };

        struct bios_info {
            static char manufacturer[256];
            static char model[128];
            static bool cached;

            static constexpr const char* fetch_manufacturer() noexcept {
                return manufacturer;
            }

            static constexpr const char* fetch_model() noexcept {
                return model;
            }

            static VMAWARE_CONSTEXPR void store_manufacturer(const char* VMAWARE_RESTRICT s) noexcept {
                if (!s) {
                    manufacturer[0] = '\0';
                    return;
                }
                const size_t cap = sizeof(manufacturer) - 1;

                size_t n = 0;
                while (n < cap && s[n] != '\0') {
                    n++;
                }

                const size_t tocopy = n;
                for (size_t i = 0; i < tocopy; ++i) {
                    manufacturer[i] = s[i];
                }
                *(manufacturer + tocopy) = '\0';
                cached = true;
            }

            static VMAWARE_CONSTEXPR void store_model(const char* VMAWARE_RESTRICT s) noexcept {
                if (!s) { 
                    model[0] = '\0';
                    return; 
                }
                const size_t cap = sizeof(manufacturer) - 1;

                size_t n = 0;
                while (n < cap && s[n] != '\0') {
                    n++;
                }

                const size_t tocopy = n;
                for (size_t i = 0; i < tocopy; ++i) {
                    model[i] = s[i];
                }
                *(model + tocopy) = '\0';
                cached = true;
            }

            static bool is_cached() noexcept {
                return cached; 
            }
        };

    #if (VMAWARE_WINDOWS)
        struct module {
            static HMODULE& fetch_ntdll() noexcept {
                static HMODULE handle = nullptr;
                return handle;
            }

            static HMODULE& fetch_kernel32() noexcept {
                static HMODULE handle = nullptr;
                return handle;
            }

            static void store(const HMODULE ntdll, const HMODULE kernel32) noexcept {
                fetch_ntdll() = ntdll;
                fetch_kernel32() = kernel32;
                is_cached() = true;
            }

            static bool& is_cached() noexcept {
                static bool cached = false;
                return cached;
            }
        };
    #endif
    };

#if (VMAWARE_WINDOWS)
    /* Timing attacks helper functionalities */
    #if (VMAWARE_X86)
    struct timer {
    #if (VMAWARE_X86_64)
        using timer_tick_t = u64;
    #else
        using timer_tick_t = u32;
    #endif

    #if (VMAWARE_MSVC)
        #pragma warning(push)
        #pragma warning(disable: 4324) 
    #endif
        /* Align to prevent false sharing when triggering hypervisor exits with the intentional data race condition */
        struct alignas(64) cache_state {
            alignas(64) volatile timer_tick_t counter { 0 };
            alignas(64) std::atomic<bool> start_test{ false };
            alignas(64) std::atomic<bool> test_done{ false };
        };
    #if (VMAWARE_MSVC)
        #pragma warning(pop)
    #endif

        #define VMAWARE_STR2(x) #x
        #define VMAWARE_STR(x) VMAWARE_STR2(x)

        struct config {
            [[nodiscard]] static VMAWARE_CONSTEXPR u32 get_seed() noexcept {
                constexpr char s[] = __DATE__ " " __TIME__ " " __FILE__ " " VMAWARE_STR(__LINE__);
                u32 h = 2166136261u;
                for (char c : s) {
                    if (!c) {
                        break;
                    }
                    h ^= static_cast<unsigned char>(c);
                    h *= 16777619u;
                }
                return h;
            }

            [[nodiscard]] static constexpr size_t clamp_c11(const size_t val, const size_t min_val, const size_t max_val) noexcept {
                return (val < min_val) ? min_val : ((val > max_val) ? max_val : val);
            }

            [[nodiscard]] static size_t generate_batch_size(const u32 ct_seed) noexcept {
                /*
                 * Important so that hypervisor can't predict how many samples we will collect
                 * stack-only / ASLR-derived component (no APIs, no interceptable instructions by hypervisors)
                 */
                u64 seed = 0;
                seed ^= static_cast<u64>(ct_seed);

                u64 local1 = 0;
                u64 local2 = 0;
                u64 local3 = 0;

                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&seed));
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&local1)) << 1;
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&local2)) << 2;
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&local3)) << 3;

                seed ^= seed >> 33;
                seed *= 0xff51afd7ed558ccdULL;
                seed ^= seed >> 33;
                seed *= 0xc4ceb9fe1a85ec53ULL;
                seed ^= seed >> 33;

                std::seed_seq seq{
                    static_cast<u32>(seed),
                    static_cast<u32>(seed >> 32),
                    static_cast<u32>(seed ^ 0x9e3779b9u),
                    ct_seed
                };

                std::mt19937 gen(seq);
                return std::uniform_int_distribution<size_t>(500, 1000)(gen);
            }
        };

        struct scheduler {
            
            /*
             *  Golden Rules (must happen ALWAYS; if they don't happen the check should be aborted):
             *  1. The check needs AT LEAST two different physical cores, so if one single core is detected, returns {}
             *  2. The counter thread should always be in the middle available physical CPU when there's more than 2 cores, and in core 2 (1-indexed) when there's 2 cores
             *  3. The counter thread and the measurement thread can NEVER be in the same physical core (SMT siblings strictly excluded).
             *
             *  Silver Rules (in order of priority):
             *  1. Same NUMA Node (+1000) & Same L3 Cache / CCD domain (+500) to ensure minimal interconnect & MESI invalidation latency.
             *  2. Prioritize higher-performance pipelines (P-cores) over efficiency-oriented pipelines (E-cores) (+800) for dedicated L2 cache pipelines.
             *  3. Deduct points (-800) for candidate cores that share an L2 cache cluster with the counter thread (targeting Intel E-core cluster bottlenecks).
             *  4. Prioritize cores with matching efficiency classes (+100) to align DVFS frequency scaling domains.
             *  5. Prefer Primary SMT thread (+20) over secondary hyperthread siblings.
             *  6. Apply a minor index-distance penalty (-1 per logical distance) to select the closest neighbor on the ring bus.
             *  7. Penalize edge logical cores and Physical Core 0 (-50) to avoid OS interrupt and DPC scheduler noise.
            */
            [[nodiscard]] static GROUP_AFFINITY get_mask(const bool measurement) {
                const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
                const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);

                GROUP_AFFINITY active_group_aff{};
                DWORD_PTR proc_mask = 0, sys_mask = 0;

                if (GetProcessAffinityMask(current_process, &proc_mask, &sys_mask) && proc_mask) {
                    active_group_aff.Mask = proc_mask;

                    GROUP_AFFINITY thread_aff{};
                    if (GetThreadGroupAffinity(current_thread, &thread_aff)) {
                        active_group_aff.Group = thread_aff.Group;
                    }
                    else {
                        active_group_aff.Group = 0;
                    }
                }
                else {
                    return {};
                }

                const WORD target_group = active_group_aff.Group;
                const KAFFINITY target_mask = active_group_aff.Mask;

                alignas(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) BYTE stack_topo[4096]{};
                DWORD len = sizeof(stack_topo);

                std::vector<BYTE> heap_topo;
                PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX topo_ptr =
                    reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(stack_topo);

                if (!GetLogicalProcessorInformationEx(RelationAll, topo_ptr, &len)) {
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > sizeof(stack_topo)) {
                        heap_topo.resize(len);
                        topo_ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(heap_topo.data());
                        if (!GetLogicalProcessorInformationEx(RelationAll, topo_ptr, &len)) {
                            return {};
                        }
                    }
                    else {
                        return {};
                    }
                }

                struct GroupCpu {
                    DWORD LogicalId = 0xFFFFFFFFu;
                    DWORD CoreId = 0xFFFFFFFFu;
                    DWORD NumaNode = 0xFFFFFFFFu;
                    DWORD L2CacheId = 0xFFFFFFFFu;
                    DWORD L3CacheId = 0xFFFFFFFFu;
                    BYTE  EfficiencyClass = 0;
                    bool  IsPrimarySmt = false;
                };

                GroupCpu group_cpus[64]{};
                DWORD active_cpu_count = 0;
                DWORD idxs[64]{};

                for (DWORD i = 0; i < 64; ++i) {
                    if (target_mask & (1ull << i)) {
                        group_cpus[i].LogicalId = i;
                        idxs[active_cpu_count++] = i;
                    }
                }

                if (active_cpu_count < 2) {
                    return {};
                }

                DWORD core_count = 0;
                DWORD cache_count = 0;
                size_t offset = 0;

                while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) <= len) {
                    auto* ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                        reinterpret_cast<BYTE*>(topo_ptr) + offset
                    );

                    if (ptr->Size < sizeof(LOGICAL_PROCESSOR_RELATIONSHIP) + sizeof(DWORD) || offset + ptr->Size > len) {
                        return {};
                    }

                    switch (ptr->Relationship) {
                    case RelationProcessorCore: {
                        const DWORD core_id = core_count++;
                        const BYTE efficiency = ptr->Processor.EfficiencyClass;

                        for (DWORD g = 0; g < ptr->Processor.GroupCount; ++g) {
                            if (ptr->Processor.GroupMask[g].Group == target_group) {
                                const KAFFINITY mask = ptr->Processor.GroupMask[g].Mask;
                                bool first_smt = true;
                                for (DWORD bit = 0; bit < 64; ++bit) {
                                    if (mask & (1ull << bit)) {
                                        if (group_cpus[bit].LogicalId != 0xFFFFFFFFu) {
                                            group_cpus[bit].CoreId = core_id;
                                            group_cpus[bit].EfficiencyClass = efficiency;
                                            group_cpus[bit].IsPrimarySmt = first_smt;
                                            first_smt = false;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case RelationNumaNode: {
                        const DWORD node_id = ptr->NumaNode.NodeNumber;
                        const WORD g_count = (ptr->NumaNode.GroupCount > 0) ? ptr->NumaNode.GroupCount : 1;
                        for (WORD g = 0; g < g_count; ++g) {
                            const GROUP_AFFINITY& g_aff = (ptr->NumaNode.GroupCount > 1)
                                ? ptr->NumaNode.GroupMasks[g]
                                : ptr->NumaNode.GroupMask;

                            if (g_aff.Group == target_group) {
                                const KAFFINITY mask = g_aff.Mask;
                                for (DWORD bit = 0; bit < 64; ++bit) {
                                    if (mask & (1ull << bit)) {
                                        if (group_cpus[bit].LogicalId != 0xFFFFFFFFu) {
                                            group_cpus[bit].NumaNode = node_id;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case RelationCache: {
                        const WORD group_count_cache = (ptr->Cache.GroupCount > 0) ? ptr->Cache.GroupCount : 1;
                        const DWORD cache_id = cache_count++;

                        for (WORD g = 0; g < group_count_cache; ++g) {
                            const GROUP_AFFINITY& g_aff = ptr->Cache.GroupMasks[g];
                            if (g_aff.Group == target_group) {
                                const KAFFINITY mask = g_aff.Mask;
                                for (DWORD bit = 0; bit < 64; ++bit) {
                                    if (mask & (1ull << bit)) {
                                        if (group_cpus[bit].LogicalId != 0xFFFFFFFFu) {
                                            if (ptr->Cache.Level == 2) {
                                                group_cpus[bit].L2CacheId = cache_id;
                                            }
                                            else if (ptr->Cache.Level == 3) {
                                                group_cpus[bit].L3CacheId = cache_id;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }

                    default:
                        break;
                    }

                    offset += ptr->Size;
                }

                /* Golden Rule 1: At least two physical cores must exist */
                DWORD unique_cores[64]{};
                DWORD unique_cores_count = 0;
                DWORD core_to_primary_logical[64]{};

                for (DWORD i = 0; i < active_cpu_count; ++i) {
                    const DWORD log = idxs[i];
                    const DWORD core = group_cpus[log].CoreId;

                    if (core == 0xFFFFFFFFu) {
                        return {};
                    }

                    bool already_seen = false;
                    for (DWORD c = 0; c < unique_cores_count; ++c) {
                        if (unique_cores[c] == core) {
                            already_seen = true;
                            break;
                        }
                    }

                    if (!already_seen && unique_cores_count < 64) {
                        unique_cores[unique_cores_count] = core;
                        core_to_primary_logical[unique_cores_count] = log;
                        unique_cores_count++;
                    }
                }

                if (unique_cores_count < 2) {
                    return {}; /* Single physical core(e.g. 1 core with SMT enabled) */
                }

                /* Golden Rule 2: Counter thread always in middle physical core(or core index 1 if exactly 2 cores) */
                const DWORD counter_pos = (unique_cores_count == 2) ? 1u : (unique_cores_count / 2u);
                const DWORD counter_logical = core_to_primary_logical[counter_pos];
                const auto& counter_cpu = group_cpus[counter_logical];

                if (counter_cpu.CoreId == 0xFFFFFFFFu) {
                    return {};
                }

                if (!measurement) {
                    GROUP_AFFINITY aff{};
                    aff.Group = target_group;
                    aff.Mask = (1ull << counter_logical);
                    return aff;
                }

                BYTE max_efficiency = 0;
                for (DWORD i = 0; i < active_cpu_count; ++i) {
                    const DWORD log = idxs[i];
                    if (group_cpus[log].EfficiencyClass > max_efficiency) {
                        max_efficiency = group_cpus[log].EfficiencyClass;
                    }
                }

                const DWORD core0_id = group_cpus[idxs[0]].CoreId;
                const DWORD first_idx = idxs[0];
                const DWORD last_idx = idxs[active_cpu_count - 1];

                DWORD best_logical = 0xFFFFFFFFu;
                int best_score = (std::numeric_limits<int>::min)();

                for (DWORD i = 0; i < active_cpu_count; ++i) {
                    const DWORD logical = idxs[i];
                    if (logical == counter_logical) {
                        continue;
                    }

                    const auto& cand_cpu = group_cpus[logical];

                    /* Golden Rule 3: Never share physical core with counter thread (exclude SMT siblings) */
                    if (cand_cpu.CoreId == counter_cpu.CoreId) {
                        continue;
                    }

                    int score = 0;

                    /* Silver Rule 1: Same NUMA Node alignment (avoids cross-socket interconnect latency) */
                    if (cand_cpu.NumaNode != 0xFFFFFFFFu && cand_cpu.NumaNode == counter_cpu.NumaNode) {
                        score += 1000;
                    }

                    /* Silver Rule 1: Same L3 Cache Slice / CCD Domain (avoids AMD Infinity Fabric cross-CCD hops) */
                    if (cand_cpu.L3CacheId != 0xFFFFFFFFu && cand_cpu.L3CacheId == counter_cpu.L3CacheId) {
                        score += 500;
                    }

                    /* Silver Rule 2: Performance Core priority */
                    if (cand_cpu.EfficiencyClass == max_efficiency) {
                        score += 800;
                    }

                    /* Silver Rule 3: Shared L2 Cluster Penalty (avoids shared E-core 4-core cluster controllers) */
                    if (cand_cpu.L2CacheId != 0xFFFFFFFFu && cand_cpu.L2CacheId == counter_cpu.L2CacheId) {
                        score -= 800;
                    }

                    /* Silver Rule 4: Same Core Type / DVFS Domain alignment */
                    if (cand_cpu.EfficiencyClass == counter_cpu.EfficiencyClass) {
                        score += 100;
                    }

                    /* Silver Rule 5: Primary SMT Thread Bonus */
                    if (cand_cpu.IsPrimarySmt) {
                        score += 20;
                    }

                    /* Silver Rule 6: Silicon Ring Bus distance penalty */
                    const int dist = static_cast<int>(logical) - static_cast<int>(counter_logical);
                    score -= std::abs(dist);

                    /* Silver Rule 7: Edge logical cores & Physical Core 0 Interrupt/DPC noise penalty */
                    if (logical == first_idx || logical == last_idx || cand_cpu.CoreId == core0_id) {
                        score -= 50;
                    }

                    if (score > best_score) {
                        best_score = score;
                        best_logical = logical;
                    }
                }

                if (best_logical == 0xFFFFFFFFu) {
                    return {};
                }

                vma_debug("TIMER: Measurement thread -> CPU ", best_logical, " | Counter thread -> CPU ", counter_logical);

                GROUP_AFFINITY aff{};
                aff.Group = target_group;
                aff.Mask = (1ull << best_logical);
                return aff;
            }
        };

        struct engine {
             VMAWARE_SERIALIZE static VMAWARE_FORCE_INLINE void warmup_cpu(const bool serialize_available) noexcept {
                /* Signal Intel Speed Shift / AMD CPPC to force maximum non-AVX Turbo/P-state frequency transition */
                u64 val = 0x5a5a5a5a5a5a5a5aULL;
                for (u32 i = 0; i < 2'000'000; ++i) {
                    val = (val ^ i) * 6364136223846793005ULL + 1442695040888963407ULL;
                }
                volatile u64 compiler_sink = val;
                VMAWARE_UNUSED(compiler_sink);

                /* Warm up the decoded i-cache (DSB), BTB, and microcode sequencer */
                if (serialize_available) {
                    for (int i = 0; i < 5000; ++i) {
                        _serialize();
                        std::atomic_signal_fence(std::memory_order_seq_cst);
                    }
                }
                else {
                    for (int i = 0; i < 5000; ++i) {
                        _mm_lfence();
                        std::atomic_signal_fence(std::memory_order_seq_cst);
                    }
                }
             }

            [[nodiscard]] static timer_tick_t calculate_latency(const std::vector<timer_tick_t>& samples_in) {
                if (samples_in.empty()) {
                    return 0;
                }
                const size_t N = samples_in.size();
                if (N == 1) {
                    return samples_in[0];
                }

                /* Create a local copy to sort */
                std::vector<timer_tick_t> s = samples_in;
                std::sort(s.begin(), s.end());

                /* Discard the lower 25% and upper 25%, leaving the middle 50% */
                const size_t low_idx = N / 4;
                const size_t high_idx = (3 * N) / 4;

                double sum = 0;
                size_t count = 0;
                for (size_t i = low_idx; i < high_idx; ++i) {
                    sum += s[i];
                    count++;
                }

                /* Fallback to the median if the dataset is too small */
                if (count == 0) {
                    return s[N / 2];
                }

                /* Compute the average of the middle 50% and round to the nearest integer */
                return static_cast<timer_tick_t>((sum / count) + 0.5);
            }

            static VMAWARE_FORCE_INLINE void burn_random_cycles(const u32 ct_seed, const timer_tick_t v_post, const timer_tick_t r_post) noexcept {
                /*
                 * The internal pseudo-random number generator (PRNG) variables like u64 seed and volatile u64 x can be kept as u64
                 * because they are simple register-only PRNG arithmetic and benefit from the extra 64-bit entropy space even on 32-bit platforms
                 */
                u64 seed = ct_seed;
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&seed));
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&v_post)) << 1;
                seed ^= static_cast<u64>(reinterpret_cast<std::uintptr_t>(&r_post)) << 2;
                seed ^= seed >> 33;
                seed *= 0xff51afd7ed558ccdULL;
                seed ^= seed >> 33;
                seed *= 0xc4ceb9fe1a85ec53ULL;
                seed ^= seed >> 33;

                /* 64u is the minimum amount of work every time, 0x1FFu controls how much the count varies */
                const u32 rounds = 64u + static_cast<u32>(seed & 0x7FFu);
                volatile u64 x = seed | 1ULL;

                for (u32 i = 0; i < rounds; ++i) {
                    x = x * 6364136223846793005ULL + 1ULL;
                    x ^= x >> 17;
                }

                std::atomic_signal_fence(std::memory_order_acq_rel);
            }
        };
    };
    #endif

    /* Memory related functions */
    struct memory {
        /* Uninstrumented indirect-call invokers */
        VMAWARE_NO_CFG static void execute(const void* pointer) noexcept {
            using func_t = void(*)();
            reinterpret_cast<func_t>(const_cast<void*>(pointer))();
        }

        VMAWARE_NO_CFG static void execute(const void* pointer, void* frame, uintptr_t stack32_ptr, u64* saved_rsp) noexcept {
            using func_t = void(*)(void*, uintptr_t, u64*);
            reinterpret_cast<func_t>(const_cast<void*>(pointer))(frame, stack32_ptr, saved_rsp);
        }

        VMAWARE_NO_CFG static void execute(const void* pointer, void* vmcall_info, void* vmcall_result) noexcept {
            using func_t = void(*)(void*, void*);
            reinterpret_cast<func_t>(const_cast<void*>(pointer))(vmcall_info, vmcall_result);
        }

        inline static DWORD execute_handler(const void* pointer) noexcept {
            DWORD exception_status = 0;
            __try {
                execute(pointer);
            }
            __except (exception_status = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {}
            return exception_status;
        };

        /* Retrieves the addresses of specified functions from a loaded module using the export directory, manual implementation of GetProcAddress without PE export forwarding parsing */
        static void get_function(const HMODULE module, const char* const VMAWARE_RESTRICT names[], void** const VMAWARE_RESTRICT functions, const size_t count, const bool cache_result = true) {
            VMAWARE_ASSUME(names != nullptr);
            VMAWARE_ASSUME(functions != nullptr);

            using func_map = std::unordered_map<std::string, void*>;
            static std::unordered_map<HMODULE, func_map> function_cache;

            if (VMAWARE_UNLIKELY(!functions || !names || count == 0)) {
                return;
            }

            std::memset(functions, 0, count * sizeof(void*));

            if (!module) {
                return;
            }

            BYTE* base = reinterpret_cast<BYTE*>(module);

            size_t module_size = 0;        
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(base, &mbi, sizeof(mbi))) {
                module_size = static_cast<size_t>(mbi.RegionSize);
            }
            else {
                return;
            }

            auto valid_range = [&](size_t offset, size_t sz) noexcept -> bool {
                return (sz > 0) && (offset < module_size) && (sz <= module_size - offset);
            };

            auto cstr_from_rva = [&](DWORD rva) noexcept -> const char* {
                if (!valid_range(static_cast<size_t>(rva), 1)) {
                    return nullptr;
                }

                const char* start = reinterpret_cast<const char*>(base + rva);
                const size_t remaining = module_size - static_cast<size_t>(rva);

                if (std::memchr(start, '\0', remaining)) {
                    return start;
                }

                return nullptr;
            };

            /* Validate DOS header */
            if (VMAWARE_UNLIKELY(!valid_range(0, sizeof(IMAGE_DOS_HEADER)))) {
                return;
            }
            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (VMAWARE_UNLIKELY(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)) {
                return;
            }

            /* e_lfanew -> NT headers */
            if (VMAWARE_UNLIKELY(dosHeader->e_lfanew < 0)) {
                return;
            }
            const size_t e_lfanew = static_cast<size_t>(dosHeader->e_lfanew);
            if (VMAWARE_UNLIKELY(!valid_range(e_lfanew, sizeof(IMAGE_NT_HEADERS)))) {
                return;
            }
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + e_lfanew);
            if (VMAWARE_UNLIKELY(ntHeaders->Signature != IMAGE_NT_SIGNATURE)) {
                return;
            }

            const size_t sizeOfImage = static_cast<size_t>(ntHeaders->OptionalHeader.SizeOfImage);
            if (sizeOfImage != 0 && sizeOfImage > module_size) {
                module_size = sizeOfImage;
            }

            /* Check export data directory exists */
            if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
                return;
            }

            const auto& dd = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (dd.VirtualAddress == 0 || dd.Size == 0) {
                return;
            }

            /* Validate export directory fits */
            if (!valid_range(static_cast<size_t>(dd.VirtualAddress), sizeof(IMAGE_EXPORT_DIRECTORY))) {
                return;
            }

            const auto* exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dd.VirtualAddress);

            const DWORD nameCount = exportDir->NumberOfNames;
            const DWORD funcCount = exportDir->NumberOfFunctions;

            constexpr DWORD MAX_NAMES = 1u << 20;
            if (nameCount == 0 || nameCount > MAX_NAMES) {
                return;
            }
            if (funcCount == 0 || funcCount > MAX_NAMES) {
                return;
            }

            const DWORD addr_names = exportDir->AddressOfNames;
            const DWORD addr_funcs = exportDir->AddressOfFunctions;
            const DWORD addr_ord = exportDir->AddressOfNameOrdinals;

            if (!valid_range(static_cast<size_t>(addr_names), static_cast<size_t>(nameCount) * sizeof(DWORD))) {
                return;
            }
            if (!valid_range(static_cast<size_t>(addr_funcs), static_cast<size_t>(funcCount) * sizeof(DWORD))) {
                return;
            }
            if (!valid_range(static_cast<size_t>(addr_ord), static_cast<size_t>(nameCount) * sizeof(WORD))) {
                return;
            }

            const DWORD* nameRvas = reinterpret_cast<const DWORD*>(base + addr_names);
            const DWORD* funcRvas = reinterpret_cast<const DWORD*>(base + addr_funcs);
            const WORD* ordinals = reinterpret_cast<const WORD*>(base + addr_ord);

            for (size_t i = 0; i < count; ++i) {
                const char* current_name = names[i];
                if (!current_name) {
                    continue;
                }
                const std::string s_name(current_name);

                /* Only query and populate the cache if it's not a dynamically loaded module with LoadLibraryEx */
                if (cache_result) {
                    func_map& module_cache = function_cache[module];
                    const auto cache_it = module_cache.find(s_name);
                    if (VMAWARE_LIKELY(cache_it != module_cache.end())) {
                        functions[i] = cache_it->second;
                        continue;
                    }
                }

                /* Binary search over names */
                DWORD lo = 0, hi = nameCount;
                while (lo < hi) {
                    const DWORD mid = lo + (hi - lo) / 2;
                    const DWORD midNameRva = nameRvas[mid];
                    const char* midName = cstr_from_rva(midNameRva);
                    if (!midName) {
                        lo = hi;
                        break;
                    }

                    const int cmp = strcmp(current_name, midName);
                    if (cmp > 0) {
                        lo = mid + 1;
                    }
                    else {
                        hi = mid;
                    }
                }

                if (lo < nameCount) {
                    const char* candidateName = cstr_from_rva(nameRvas[lo]);
                    if (candidateName && strcmp(current_name, candidateName) == 0) {
                        const WORD nameOrdinal = ordinals[lo];
                        if (static_cast<DWORD>(nameOrdinal) >= funcCount) {
                            continue;
                        }
                        const DWORD funcRva = funcRvas[nameOrdinal];
                        if (!valid_range(static_cast<size_t>(funcRva), 1)) {
                            continue;
                        }
                        void* addr = reinterpret_cast<void*>(base + funcRva);
                        functions[i] = addr;

                        if (cache_result) {
                            function_cache[module][s_name] = addr;
                        }
                        continue;
                    }
                }
            }
        }

        [[nodiscard]] static HMODULE get_module(const bool get_ntdll) noexcept {
            struct custom_unicode_string {
                unsigned short length;
                unsigned short max_length;
                wchar_t* buffer;
            };

            struct custom_ldr_entry {
                void* reserved1[2];
                LIST_ENTRY in_memory_links;
                void* reserved2[2];
                void* dll_base;
                void* reserved3[2];
                custom_unicode_string full_name;
                custom_unicode_string base_name;
            };

            struct custom_peb {
                unsigned char reserved1[2];
                unsigned char being_debugged;
                unsigned char reserved2[1];
                void* mutant;
                void* image_base_address;
                struct {
                    unsigned char reserved3[8];
                    void* reserved4[3];
                    LIST_ENTRY in_memory_list;
                }*ldr;
            };

            if (memo::module::is_cached()) {
                return get_ntdll ? memo::module::fetch_ntdll() : memo::module::fetch_kernel32();
            }

            custom_peb* peb = nullptr;

        #if (VMAWARE_X86_64)
            #if (VMAWARE_MSVC && !VMAWARE_CLANG)
                peb = reinterpret_cast<custom_peb*>(__readgsqword(0x60));
            #else
                asm("movq %%gs:0x60, %0" : "=r"(peb));
            #endif
        #elif (VMAWARE_X86_32)
            #if (VMAWARE_MSVC && !VMAWARE_CLANG)
                peb = reinterpret_cast<custom_peb*>(__readfsdword(0x30));
            #else
                asm("movl %%fs:0x30, %0" : "=r"(peb));
            #endif
        #endif

            if (!peb || !peb->ldr) {
                return GetModuleHandleW(get_ntdll ? L"ntdll.dll" : L"kernel32.dll");
            }

            auto matches = [](const wchar_t* s1, const wchar_t* s2, const unsigned short len) noexcept -> bool {
                for (unsigned short i = 0; i < len; ++i) {
                    if ((s1[i] | 0x20) != (s2[i] | 0x20)) {
                        return false;
                    }
                }
                return true;
            };

            HMODULE res_ntdll = nullptr;
            HMODULE res_k32 = nullptr;

            LIST_ENTRY* head = &peb->ldr->in_memory_list;
            for (LIST_ENTRY* cur = head->Flink; cur != nullptr && cur != head; cur = cur->Flink) {
                auto* ent = reinterpret_cast<custom_ldr_entry*>(reinterpret_cast<char*>(cur) - (sizeof(void*) * 2));
                if (!ent || !ent->base_name.buffer || ent->base_name.length == 0) {
                    continue;
                }

                const unsigned short len_chars = ent->base_name.length / sizeof(wchar_t);
                const wchar_t* buf = ent->base_name.buffer;

                if ((len_chars == 9 && matches(buf, L"ntdll.dll", 9)) || (len_chars == 5 && matches(buf, L"ntdll", 5))) {
                    res_ntdll = reinterpret_cast<HMODULE>(ent->dll_base);
                }
                else if ((len_chars == 12 && matches(buf, L"kernel32.dll", 12)) || (len_chars == 8 && matches(buf, L"kernel32", 8))) {
                    res_k32 = reinterpret_cast<HMODULE>(ent->dll_base);
                }

                if (res_ntdll && res_k32) {
                    break;
                }
            }

            if (res_ntdll || res_k32) {
                memo::module::store(res_ntdll, res_k32);
            }

            if (get_ntdll) {
                return res_ntdll ? res_ntdll : GetModuleHandleW(L"ntdll.dll");
            }
            return res_k32 ? res_k32 : GetModuleHandleW(L"kernel32.dll");
        }
    };
#endif

    /* String utilities */
    struct string {
        /* Converts a single character to lowercase */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR char to_lower(char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
        }

        /* Converts a single character to uppercase */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR char to_upper(char c) noexcept {
            return (c >= 'a' && c <= 'z') ? static_cast<char>(c & 0xDF) : c;
        }

        /* Checks if a string starts with a specific prefix (case-sensitive) */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 bool starts_with(const char* str, const char* prefix) noexcept {
            if (!str || !prefix) {
                return false;
            }
            while (*prefix) {
                if (*str++ != *prefix++) {
                    return false;
                }
            }
            return true;
        }

        /* Finds a substring inside a null-terminated string (case-sensitive) */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 const char* find(const char* haystack, const char* needle) noexcept {
            if (!haystack || !needle) {
                return nullptr;
            }
            if (!*needle) {
                return haystack;
            }
            for (; *haystack; ++haystack) {
                if (*haystack == *needle) {
                    const char* h = haystack;
                    const char* n = needle;
                    while (*h && *n && *h == *n) {
                        h++;
                        n++;
                    }
                    if (!*n) {
                        return haystack;
                    }
                }
            }
            return nullptr;
        }

        /* Finds a substring inside a null-terminated string (case-insensitive) */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 const char* find_ci(const char* haystack, const char* needle) noexcept {
            if (!haystack || !needle) {
                return nullptr;
            }
            if (!*needle) {
                return haystack;
            }
            const char n0_lower = to_lower(*needle);
            for (; *haystack; ++haystack) {
                if (to_lower(*haystack) == n0_lower) {
                    const char* h = haystack;
                    const char* n = needle;
                    while (*h && *n && to_lower(*h) == to_lower(*n)) {
                        h++;
                        n++;
                    }
                    if (!*n) {
                        return haystack;
                    }
                }
            }
            return nullptr;
        }

        /* Checks if a std::string contains a substring (case-sensitive) */
        static VMAWARE_FORCE_INLINE bool contains(const std::string& base_str, const char* keyword) noexcept {
            return base_str.find(keyword) != std::string::npos;
        }

        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 bool contains_ci(const char* haystack, const char* needle) noexcept {
            if (!haystack || !needle) {
                return false;
            }
            if (!*needle) {
                return true;
            }
            const char n0_lower = to_lower(*needle);
            for (; *haystack; ++haystack) {
                if (to_lower(*haystack) == n0_lower) {
                    const char* h = haystack;
                    const char* n = needle;
                    while (*h && *n && to_lower(*h) == to_lower(*n)) {
                        h++;
                        n++;
                    }
                    if (!*n) {
                        return true;
                    }
                }
            }
            return false;
        }

        /* Compares two null-terminated strings for equality (case-insensitive) */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 bool equals_ci(const char* s1, const char* s2) noexcept {
            if (!s1 || !s2) {
                return s1 == s2;
            }
            while (*s1 && *s2) {
                if (to_lower(*s1) != to_lower(*s2)) {
                    return false;
                }
                s1++;
                s2++;
            }
            return *s1 == *s2;
        }

        /* Converts a std::string to lowercase in place */
        static VMAWARE_FORCE_INLINE void to_lower_inplace(std::string& str) noexcept {
            const size_t len = str.length();
            for (size_t i = 0; i < len; ++i) {
                str[i] = to_lower(str[i]);
            }
        }

        /* Trims leading and trailing whitespaces from a std::string in place */
        static VMAWARE_FORCE_INLINE void trim_inplace(std::string& s) noexcept {
            while (!s.empty() && is_space(s.front())) {
                s.erase(s.begin());
            }
            while (!s.empty() && is_space(s.back())) {
                s.pop_back();
            }
        }

        /* Trims leading whitespaces from a null-terminated string pointer */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR_20 const char* ltrim(const char* str) noexcept {
            if (!str) {
                return nullptr;
            }
            while (*str && is_space(*str)) {
                str++;
            }
            return str;
        }

        /* Checks if a std::string consists only of numerical digits */
        static VMAWARE_FORCE_INLINE bool is_numeric(const std::string& s) noexcept {
            if (s.empty()) {
                return false;
            }
            const size_t len = s.length();
            for (size_t i = 0; i < len; ++i) {
                if (!is_digit(s[i])) {
                    return false;
                }
            }
            return true;
        }

        /* Helper to check for ASCII spaces (avoids locale overhead) */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR bool is_space(char c) noexcept {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
        }

        /* Helper to check for ASCII digits */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR bool is_digit(char c) noexcept {
            return c >= '0' && c <= '9';
        }

        /* Helper to check for hexadecimal characters */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR bool is_hex(char c) noexcept {
            return (c >= '0' && c <= '9') || (to_lower(c) >= 'a' && to_lower(c) <= 'f');
        }

        /* Helper to check if a character is alphanumeric */
        static VMAWARE_FORCE_INLINE VMAWARE_CONSTEXPR bool is_alnum(char c) noexcept {
            return (to_lower(c) >= 'a' && to_lower(c) <= 'z') || is_digit(c);
        }
    };

    /* Miscellaneous functionalities */
    struct util {
        [[nodiscard]] static constexpr bool is_unsupported(const VM::enum_flags flag) noexcept {
            return (flag >= VM::HYPERVISOR_BIT && flag <= VM::KGT_SIGNATURE) ? false :
            #if (VMAWARE_LINUX)
                !(flag >= LINUX_START && flag <= LINUX_END);
            #elif (VMAWARE_WINDOWS)
                !(flag >= WINDOWS_START && flag <= WINDOWS_END);
            #elif (VMAWARE_APPLE) 
                !(flag >= MACOS_START && flag <= MACOS_END);
            #else
                false;
            #endif
        }

    #if (VMAWARE_LINUX)
        /* Fetch file data */
        [[nodiscard]] static std::string read_file(const char* raw_path) {
            VMAWARE_ASSUME(raw_path != nullptr);
            std::string path;
            const std::string raw_path_str = raw_path;

            /* Replace the "~" part with the home directory */
            if (raw_path[0] == '~') {
                const char* home = std::getenv("HOME");
                if (home) {
                    path = std::string(home) + raw_path_str.substr(1);
                }
            } else {
                path = raw_path;
            }

            if (!exists(path.c_str())) {
                return "";
            }

            std::ifstream file{};
            std::string data{};
            std::string line{};

            file.open(path);

            if (file.is_open()) {
                while (std::getline(file, line)) {
                    data += line + "\n";
                }
            }

            file.close();
            return data;
        }

        [[nodiscard]] static bool exists(const char* path) {
        #if (VMAWARE_CPP >= 17)
            return std::filesystem::exists(path);
        #elif (VMAWARE_CPP >= 11)
            struct stat buffer;
            return (stat(path, &buffer) == 0);
        #endif
        }

        [[nodiscard]] static bool is_directory(const char* path) {
            VMAWARE_ASSUME(path != nullptr);
            struct stat info{};
            if (stat(path, &info) != 0) {
                return false;
            }
            return (info.st_mode & S_IFDIR); /* check if directory */
        }
    #endif

        /* Fetch the file but in binary form */
        [[nodiscard]] static std::vector<u8> read_file_binary(const char* file_path) {
            VMAWARE_ASSUME(file_path != nullptr);
            std::ifstream file(file_path, std::ios::binary);

            if (!file) {
                return {};
            }

            std::vector<u8> buffer;
            std::istreambuf_iterator<char> it(file);
            const std::istreambuf_iterator<char> end;

            while (it != end) {
                buffer.push_back(static_cast<u8>(*it));
                ++it;
            }

            file.close();

            return buffer;
        }

        /* Wrapper for std::make_unique because it's not available for C++11 */
        template<typename T, typename... Args>
        [[nodiscard]] static std::unique_ptr<T> make_unique(Args&&... args) {
        #if (VMAWARE_CPP < 14)
            return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
        #else
            return std::make_unique<T>(std::forward<Args>(args)...);
        #endif
        }

        [[nodiscard]] static bool is_admin() noexcept {
        #if (VMAWARE_LINUX || VMAWARE_APPLE)
            const uid_t uid = getuid();
            const uid_t euid = geteuid();

            return (
                (uid != euid) ||
                (euid == 0)
            );
        #elif (VMAWARE_WINDOWS)
            bool is_admin = false;
            HANDLE hToken = nullptr;
            const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
            if (OpenProcessToken(current_process, TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation{};
                DWORD dwSize;
                if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                    if (elevation.TokenIsElevated)
                        is_admin = true;
                }
                CloseHandle(hToken);
            }
            return is_admin;
        #else
            return true;
        #endif
        }

        [[nodiscard]] static bool find(const std::string& base_str, const char* keyword) noexcept {
            VMAWARE_ASSUME(keyword != nullptr);
            return string::contains(base_str, keyword);
        };

        [[nodiscard]] static i32 popcount(u64 v) noexcept {
        #if (VMAWARE_GCC) || (VMAWARE_CLANG)
            return __builtin_popcountll(v);
        #elif (VMAWARE_MSVC)
            #if (VMAWARE_X86_32)
                return static_cast<int>(
                    __popcnt(static_cast<unsigned int>(v)) +
                    __popcnt(static_cast<unsigned int>(v >> 32))
                );
            #elif (VMAWARE_X86_64)
                return static_cast<int>(__popcnt64(static_cast<unsigned long long>(v)));
            #else
                i32 c = 0;
                while (v) {
                    v &= v - 1;
                    ++c;
                }
                return c;
            #endif
        #else
            i32 c = 0;
            while (v) {
                v &= v - 1;
                ++c;
            }
            return c;
        #endif
        };

        static std::string narrow_wide(const wchar_t* wstr) {
            if (VMAWARE_UNLIKELY(!wstr)) {
                return {};
            }
            VMAWARE_ASSUME(wstr != nullptr);

            std::string result;
            const wchar_t* p = wstr;

            while (*p) {
                result.push_back(
                    (static_cast<u32>(*p) < 128)
                    ? static_cast<char>(*p)
                    : '?'
                );
                ++p;
            }

            return result;
        }

        static void append_to_stream(std::ostringstream& oss, const wchar_t* arg) {
            oss << narrow_wide(arg);
        }

        static void append_to_stream(std::ostringstream& oss, const std::wstring& ws) {
            oss << narrow_wide(ws.c_str());
        }

        static void append_to_stream(std::ostringstream& oss, const std::string& s) {
            oss << s;
        }

        static void append_to_stream(std::ostringstream& oss, const char* s) {
            if (s) {
                oss << s;
            }
        }

        static void append_to_stream(std::ostringstream& oss, const char c) {
            oss << c;
        }

        static void append_to_stream(std::ostringstream& oss, const bool b) {
            oss << (b ? "true" : "false");
        }

        template <typename T>
        static typename std::enable_if<
            !std::is_convertible<T, std::wstring>::value &&
            !std::is_same<typename std::decay<T>::type, wchar_t*>::value &&
            !std::is_same<typename std::decay<T>::type, const wchar_t*>::value &&
            !std::is_same<typename std::decay<T>::type, std::string>::value &&
            !std::is_same<typename std::decay<T>::type, const char*>::value &&
            !std::is_same<typename std::decay<T>::type, char*>::value,
            void
        >::type
            append_to_stream(std::ostringstream& oss, T&& arg)
        {
            oss << std::forward<T>(arg);
        }

        static VMAWARE_CONSTEXPR void print_to_stream(std::ostringstream&) noexcept {}

        template <typename... Args>
        static void print_to_stream(std::ostringstream& oss, Args&&... args) noexcept {
            using expander = int[];
            (void)expander {
                0,
                ((void)append_to_stream(oss, std::forward<Args>(args)), 0)...
            };
        }

        template <typename... Args>
        static void debug_msg(Args&&... message) {
            static std::unordered_set<std::string> printed_messages;

            std::ostringstream oss;
            print_to_stream(oss, std::forward<Args>(message)...);

            std::string msg_content = oss.str();

            if (printed_messages.find(msg_content) == printed_messages.end()) {
            #if (VMAWARE_LINUX || VMAWARE_APPLE)
                constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
                constexpr const char* bold = "\033[1m";
                constexpr const char* blue = "\x1B[38;2;00;59;193m";
                constexpr const char* ansiexit = "\x1B[0m";

                std::cerr
                    << black_bg
                    << bold << "["
                    << blue << "DEBUG"
                    << ansiexit
                    << bold << black_bg << "]"
                    << ansiexit
                    << " ";
            #else
                std::cerr << "[DEBUG] ";
            #endif

                std::cerr << msg_content << '\n';

                printed_messages.insert(std::move(msg_content));
            }
        }

        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const char* cmd) {
        #if (VMAWARE_CPP < 14)
            VMAWARE_UNUSED(cmd);
            return util::make_unique<std::string>();
        #else
            #if (VMAWARE_LINUX || VMAWARE_APPLE)
                VMAWARE_ASSUME(cmd != nullptr);
                struct file_deleter {
                    void operator()(FILE* f) const noexcept {
                        if (f) {
                            pclose(f);
                        };
                    }
                };

                std::unique_ptr<FILE, file_deleter> const pipe(popen(cmd, "r"), file_deleter()); /* NOLINT(bugprone-command-processor) */
                if (VMAWARE_UNLIKELY(!pipe)) {
                    return util::make_unique<std::string>();
                }

                std::string result;
                char buf[4096];
                while (std::fgets(buf, sizeof(buf), pipe.get()) != nullptr) {
                    result.append(buf);
                }

                if (!result.empty() && result.back() == '\n') {
                    result.pop_back();
                }

                return util::make_unique<std::string>(std::move(result));
            #else
                VMAWARE_UNUSED(cmd);
                return std::make_unique<std::string>();
            #endif
        #endif
        }


        [[nodiscard]] static bool is_proc_running(const char* executable) {
        #if (VMAWARE_LINUX)
            VMAWARE_ASSUME(executable != nullptr);
            #if (VMAWARE_CPP >= 17)
            std::error_code ec;
            auto dir_iter = std::filesystem::directory_iterator("/proc", ec);
            if (ec) {
                return false;
            }

            try {
                for (const auto& entry : dir_iter) {
                    std::error_code file_ec;
                    if (!entry.is_directory(file_ec)) {
                        continue;
                    }

                    const std::string filename = entry.path().filename().string();
            #else
                std::unique_ptr<DIR, decltype(&closedir)> dir(opendir("/proc"), closedir);
                if (!dir) {
                    vma_debug("util::is_proc_running: ", "failed to open /proc directory");
                    return false;
                }

                struct dirent* entry;
                while ((entry = readdir(dir.get())) != nullptr) {
                    std::string filename(entry->d_name);
                    if (filename == "." || filename == "..") {
                        continue;
                    }
            #endif
                if (!string::is_numeric(filename)) {
                    continue;
                }

                const std::string cmdline_file = "/proc/" + filename + "/cmdline";

                /* Read raw bytes (binary) to preserve embedded NULs */
                std::ifstream ifs(cmdline_file, std::ios::in | std::ios::binary);
                if (!ifs.is_open()) {
                    continue;
                }

                /* Read entire file into vector<char> */
                std::vector<char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                ifs.close();

                if (buf.empty()) {
                    continue;
                }

                /* Cmdline is argv0\0argv1\0..., so argv0 is bytes up to first NUL */
                const auto it_nul = std::find(buf.begin(), buf.end(), '\0');
                if (it_nul == buf.begin()) {
                    continue;
                }

                std::string const argv0(buf.begin(), it_nul);
                if (argv0.empty()) {
                    continue;
                }

                /* Extract basename of argv0 */
                const std::size_t slash_index = argv0.find_last_of('/');
                std::string const basename = (slash_index == std::string::npos) ? argv0 : argv0.substr(slash_index + 1);

                if (basename != executable) {
                    continue;
                }

                return true;
            }

        #if (VMAWARE_CPP >= 17)
            } catch (...) {}
        #endif

            return false;
        #else
            VMAWARE_UNUSED(executable);
            return false;
        #endif  
        }


        [[nodiscard]] static bool is_x86_process_on_arm() {
            static const bool cached = []() -> bool {
            #if (VMAWARE_WINDOWS)
                const char* brand = cpu::get_brand();
                if (brand && string::find(brand, "Virtual CPU")) {
                    return true;
                }

                #if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
                    const HANDLE current_process = reinterpret_cast<HANDLE>(-1);

                    USHORT proc_machine = 0;
                    USHORT native_machine = 0;

                    const HMODULE kernel32 = memory::get_module(false);
                    if (kernel32) {
                        using is_wow_64_process_2_fn = BOOL(__stdcall*)(HANDLE, USHORT*, USHORT*);
                        is_wow_64_process_2_fn is_wow_64_process_2 = reinterpret_cast<is_wow_64_process_2_fn>(GetProcAddress(kernel32, "IsWow64Process2"));

                        if (is_wow_64_process_2) {
                            if (is_wow_64_process_2(current_process, &proc_machine, &native_machine)) {
                                if ((native_machine == IMAGE_FILE_MACHINE_ARM64 || native_machine == IMAGE_FILE_MACHINE_ARMNT) &&
                                    (proc_machine == IMAGE_FILE_MACHINE_I386 || proc_machine == IMAGE_FILE_MACHINE_AMD64)) {
                                    return true;
                                }
                            }
                        }
                    }

                    if (native_machine == IMAGE_FILE_MACHINE_ARM64 || native_machine == IMAGE_FILE_MACHINE_ARMNT) {
                        if (HMODULE ntdll = memory::get_module(true)) {
                            constexpr const char* function_names[] = { "NtQueryInformationProcess" };
                            void* functions[ARRAYSIZE(function_names)] = {};
                            memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

                            using nt_query_information_process_fn = NTSTATUS(__stdcall*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                            auto nt_query_information_process = reinterpret_cast<nt_query_information_process_fn>(functions[0]);

                            if (nt_query_information_process) {
                                struct PROCESS_MACHINE_INFORMATION {
                                    USHORT ProcessMachine;
                                    USHORT Res0;
                                    DWORD MachineAttributes;
                                } pmInfo{};

                                ULONG returned_len = 0;
                                NTSTATUS status = nt_query_information_process(
                                    current_process,
                                    90, /* ProcessMachineInternalInformation */
                                    &pmInfo,
                                    sizeof(pmInfo),
                                    &returned_len
                                );

                                if (status >= 0) {
                                    if (pmInfo.ProcessMachine == IMAGE_FILE_MACHINE_I386 ||
                                        pmInfo.ProcessMachine == IMAGE_FILE_MACHINE_AMD64) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                #endif
            #endif  

                if (cpu::is_leaf_supported(cpu::leaf::hypervisor)) {
                    const std::string vendor = cpu::cpu_manufacturer(cpu::leaf::hypervisor);
                    return vendor == "VirtualApple" || vendor == "PowerVM Lx86";
                }

                return false;
            }();

            return cached;
        }


        /**
         * @brief Check what kind of Hyper-V hypervisor is running on the system
         * @note Hyper-V's presence on a host system can set certain hypervisor-related CPU flags that may appear similar to those in a virtualized environment, which can make it challenging to differentiate between an actual Hyper-V virtual machine (VM) and a host system with Hyper-V enabled.
         *       This can lead to false conclusions, where the system might mistakenly be identified as running in a Hyper-V VM, when in reality, it's simply the host system with Hyper-V features active.
         *       This check aims to distinguish between these two cases by identifying specific CPU flags and hypervisor-related artifacts that are indicative of a Hyper-V VM rather than a host system with Hyper-V enabled.
         * @returns hyperx_state enum indicating the detected state:
         *          - HYPERV_HOST for host with Hyper-V enabled
         *          - HYPERV_REAL_VM for real Hyper-V VM
         *          - HYPERV_ENLIGHTENMENT for QEMU with Hyper-V enlightenments
         *          - HYPERV_NESTED_VM for a hypervisor nested within a Hyper-V partition
         *          - HYPERV_SPOOFED for a hypervisor spoofing itself as Hyper-V
         *          - HYPERV_UNKNOWN for unknown/undetected state
         */
        [[nodiscard]] static hyperx_state hyper_x() {
        #if (!VMAWARE_WINDOWS)
            return HYPERV_UNKNOWN;
        #else
            if (memo::hyperx::is_cached()) {
                return memo::hyperx::fetch();
            }

            /* Check if hypervisor feature bit in CPUID Leaf 1, ECX bit 31 is enabled */
            auto is_hyperv_present = []() noexcept -> bool {
                u32 unused, ecx = 0;
                cpu::cpuid(unused, unused, ecx, unused, cpu::leaf::features);

                return (ecx >> 31) & 1;
            };

            /*
             * 0x40000003 on EBX indicates the flags that a parent partition specified to create a child partition (https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask)
             * some CPU models like N4200 expose 0x40000003 leaves without exposing the hypervisor bit
             */
            auto is_root_partition = []() noexcept -> bool {
                u32 ebx, unused = 0;
                cpu::cpuid(unused, ebx, unused, unused, cpu::leaf::hv_privileges);

                return (ebx & 1);
            };

            /*
             * on Hyper-V virtual machines, the cpuid function reports an EAX value of 11
             * this value is tied to the Hyper-V partition model, where each virtual machine runs as a child partition
             * essentially, it indicates that the hypervisor is managing the VM and that the VM is not running directly on hardware but rather in a virtualized environment
             */
            auto eax = []() noexcept -> u32 {
                u32 eax_reg, unused = 0;
                cpu::cpuid(eax_reg, unused, unused, unused, cpu::leaf::hypervisor);

                return eax_reg & 0xFF; /* Truncation is intentional */
            };

            /* Check whether a hypervisor is nested within a Hyper-V partition */
            auto is_hyperv_nested = []() noexcept -> bool {
                u32 eax = 0, ebx = 0, ecx = 0, edx = 0;

                cpu::cpuid(eax, ebx, ecx, edx, cpu::leaf::hv_interface);
                if (eax != 0x31237648) { /* Hv#1 interface */
                    return false;
                }

                cpu::cpuid(eax, ebx, ecx, edx, cpu::leaf::hv_nested); /* Hypervisor level of the current guest */
                const u32 guest_level = (eax >> 10) & 0xF;

                return guest_level != 0;
            };

            /* Check if the HAL path HalpInitializeErrSrc->HalpInitializeMce->HalpMceInit->HalpHvInitMcaPcrContext is initializing machine-check/WHEA state in a hypervisor-aware context */
            auto is_halh_present = []() noexcept -> bool {
                const HMODULE ntdll = memory::get_module(true);
                if (!ntdll) {
                    return true;
                }

                constexpr const char* function_names[] = {
                    "NtQuerySystemInformation"
                };
                void* functions[ARRAYSIZE(function_names)] = {};
                memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

                using nt_query_sysinfo_fn = NTSTATUS(__stdcall*)(ULONG, PVOID, ULONG, PULONG);
                nt_query_sysinfo_fn nt_query_system_information = reinterpret_cast<nt_query_sysinfo_fn>(functions[0]);
                if (!nt_query_system_information) {
                    return false;
                }

                struct entry_struct { ULONG Tag; ULONG PA; ULONG PF; SIZE_T PU; ULONG NPA; ULONG NPF; SIZE_T NPU; };
                struct info_struct { ULONG Count; entry_struct TagInfo[1]; };

                ULONG size = 1024 * 1024;
                HANDLE heap = GetProcessHeap();
                PVOID buffer = HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
                if (!buffer) {
                    return true;
                }

                ULONG needed = 0;
                while (nt_query_system_information(0x16, buffer, size, &needed) == static_cast<NTSTATUS>(0xC0000004L)) {
                    size = needed + 4096;
                    if (PVOID new_buffer = HeapReAlloc(heap, 0, buffer, size)) {
                        buffer = new_buffer;
                    }
                    else {
                        HeapFree(heap, 0, buffer);
                        return true;
                    }
                }

                const NTSTATUS status = nt_query_system_information(0x16, buffer, size, &needed);
                if (!NT_SUCCESS(status)) {
                    HeapFree(heap, 0, buffer);
                    return false;
                }

                const size_t header_offset = offsetof(info_struct, TagInfo);
                if (needed < header_offset) {
                    HeapFree(heap, 0, buffer);
                    return false;
                }

                bool found = false;
                const auto* info = static_cast<info_struct*>(buffer);
                if (info) {
                    const size_t bytes_available = needed - header_offset;
                    const size_t max_possible_count = bytes_available / sizeof(entry_struct);

                    const ULONG safe_count = (info->Count < max_possible_count) ? info->Count : static_cast<ULONG>(max_possible_count);

                    for (ULONG i = 0; i < safe_count; ++i) {
                        if (info->TagInfo[i].Tag == 0x486C6148) { /* HalH */
                            found = true;
                            break;
                        }
                    }
                }

                HeapFree(heap, 0, buffer);
                return found;
            };

            auto is_log_present = []() -> bool {
            #pragma pack(push, 1)
                struct tcg_pcr_event_header {
                    u8 pad[28];
                    u32 event_data_size;
                    u8 event_data[1];
                };
                struct tcg_efi_spec_id_event_struct_header {
                    u8 pad[24];
                    u32 number_of_algorithms;
                };
                struct tbs_context_params {
                    u32 version;
                };
            #pragma pack(pop)

                using pfn_tbsi_get_tcg_log_ex = int(__stdcall*)(u32, u8*, u32*);
                using pfn_tbsi_context_create = int(__stdcall*)(void*, void**);
                using pfn_tbsi_get_tcg_log = int(__stdcall*)(void*, u8*, u32*);
                using pfn_tbsip_context_close = int(__stdcall*)(void*);

                const HMODULE tbs_module = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!tbs_module) {
                    return true; /* If not Windows 10, return true (legit) to not false flag */
                }

                const char* function_names[] = {
                    "Tbsi_Get_TCG_Log_Ex",
                    "Tbsi_Context_Create",
                    "Tbsi_Get_TCG_Log",
                    "Tbsip_Context_Close"
                };
                constexpr size_t function_count = sizeof(function_names) / sizeof(function_names[0]);
                void* functions[function_count] = {};
                memory::get_function(tbs_module, function_names, functions, function_count);

                const pfn_tbsi_get_tcg_log_ex get_tcg_log_ex = reinterpret_cast<pfn_tbsi_get_tcg_log_ex>(functions[0]);
                const pfn_tbsi_context_create context_create = reinterpret_cast<pfn_tbsi_context_create>(functions[1]);
                const pfn_tbsi_get_tcg_log get_tcg_log = reinterpret_cast<pfn_tbsi_get_tcg_log>(functions[2]);
                const pfn_tbsip_context_close context_close = reinterpret_cast<pfn_tbsip_context_close>(functions[3]);

                if (!get_tcg_log_ex && !(context_create && get_tcg_log && context_close)) {
                    FreeLibrary(tbs_module);
                    return true; /* If not Windows 10, return true (legit) to not false flag */
                }

                u32 log_size = 0;
                u8* log_buffer = nullptr;
                int hr = -1;

                if (get_tcg_log_ex) {
                    hr = get_tcg_log_ex(0, nullptr, &log_size);
                    if ((hr == 0 || hr == static_cast<decltype(hr)>(0x80284005)) && log_size > 0) {
                        log_buffer = new u8[log_size];
                        hr = get_tcg_log_ex(0, log_buffer, &log_size);
                    }
                }
                else if (context_create && get_tcg_log && context_close) {
                    void* context = nullptr;
                    tbs_context_params params{};
                    params.version = 1;
                    hr = context_create(&params, &context);
                    if (hr == 0) {
                        hr = get_tcg_log(context, nullptr, &log_size);
                        if ((hr == 0 || hr == static_cast<decltype(hr)>(0x80284005)) && log_size > 0) {
                            log_buffer = new u8[log_size];
                            hr = get_tcg_log(context, log_buffer, &log_size);
                        }
                        context_close(context);
                    }
                }

                FreeLibrary(tbs_module);

                if (hr != 0 || !log_buffer) {
                    delete[] log_buffer;
                    return true; /* No functional TPM? */
                }

                bool found_hyperv = false;
                bool parse_error = false;
                do {
                    if (log_size < 32) {
                        parse_error = true;
                        break;
                    }
                    const auto* const first_event = reinterpret_cast<const tcg_pcr_event_header*>(log_buffer);

                    if (first_event->event_data_size > log_size - 32) {
                        parse_error = true;
                        break;
                    }
                    const size_t first_event_size = static_cast<size_t>(32) + first_event->event_data_size;
                    const bool crypto_agile = (first_event->event_data_size >= 16 && std::memcmp(first_event->event_data, "Spec ID Event03", 15) == 0);

                    struct alg_size_pair {
                        u16 alg_id;
                        u16 digest_size;
                    };

                    alg_size_pair alg_sizes[16] = {
                        {0x0004, 20}, /* SHA1 */
                        {0x000B, 32}, /* SHA256 */
                        {0x000C, 48}, /* SHA384 */
                        {0x000D, 64}, /* SHA512 */
                        {0x0012, 32}  /* SM3 */
                    };
                    size_t alg_count = 5;

                    if (crypto_agile) {
                        if (first_event->event_data_size >= sizeof(tcg_efi_spec_id_event_struct_header)) {
                            const auto* const spec_id = reinterpret_cast<const tcg_efi_spec_id_event_struct_header*>(first_event->event_data);
                            const u8* p_alg = first_event->event_data + sizeof(*spec_id);
                            if (first_event->event_data_size - sizeof(*spec_id) >= static_cast<unsigned long long>(spec_id->number_of_algorithms) * 4) {
                                for (u32 i = 0; i < spec_id->number_of_algorithms; ++i, p_alg += 4) {
                                    const u16 alg_id = *reinterpret_cast<const u16*>(p_alg);
                                    const u16 digest_size = *reinterpret_cast<const u16*>(p_alg + 2);
                                    bool updated = false;
                                    for (size_t j = 0; j < alg_count; ++j) {
                                        if (alg_sizes[j].alg_id == alg_id) {
                                            alg_sizes[j].digest_size = digest_size;
                                            updated = true;
                                            break;
                                        }
                                    }
                                    if (!updated && alg_count < 16) {
                                        alg_sizes[alg_count++] = { alg_id, digest_size };
                                    }
                                }
                            }
                            else {
                                parse_error = true;
                                break;
                            }
                        }
                        else {
                            parse_error = true;
                            break;
                        }
                    }

                    size_t offset = first_event_size;

                    constexpr const wchar_t* hyperv_targets[] = {
                        L"hvix64.exe", L"hvax64.exe", L"hvloader.dll", L"securekernel.exe",
                        L"winresume.efi", L"hiberresume.exe", L"hiberrsm.exe"
                    };

                    const auto scan_targets = [&](const u32 pcr, const u32 event_size, const u8* const event_data) -> bool {
                        if (pcr == 11 || pcr == 13) {
                            for (const auto& target : hyperv_targets) {
                                size_t target_len = 0;
                                while (target[target_len] != L'\0') {
                                    target_len++;
                                }
                                const size_t len = target_len * 2;

                                if (event_size < len) {
                                    continue;
                                }

                                for (size_t i = 0; i <= event_size - len; i += 1) {
                                    bool match = true;
                                    for (size_t j = 0; j < target_len; ++j) {
                                        const unsigned char low_byte = static_cast<unsigned char>(event_data[i + (j * 2)]);
                                        const unsigned char high_byte = static_cast<unsigned char>(event_data[i + (j * 2) + 1]);

                                        wchar_t log_char = static_cast<wchar_t>(low_byte | (high_byte << 8));
                                        wchar_t target_char = target[j];

                                        if (log_char >= L'A' && log_char <= L'Z') {
                                            log_char = log_char - L'A' + L'a';
                                        }
                                        if (target_char >= L'A' && target_char <= L'Z') {
                                            target_char = target_char - L'A' + L'a';
                                        }

                                        if (log_char != target_char) {
                                            match = false;
                                            break;
                                        }
                                    }
                                    if (match) {
                                        return true;
                                    }
                                }
                            }
                        }
                        return false;
                    };

                    while (offset < log_size) {
                        if (crypto_agile) {
                            if (offset + 12 > log_size) {
                                parse_error = true;
                                break;
                            }
                            const u32 pcr = *reinterpret_cast<const u32*>(log_buffer + offset);
                            const u32 digest_count = *reinterpret_cast<const u32*>(log_buffer + offset + 8);

                            size_t temp = offset + 12;
                            bool alg_error = false;
                            for (u32 i = 0; i < digest_count; ++i) {
                                if (log_size - temp < 2) {
                                    alg_error = true;
                                    break;
                                }
                                const u16 alg_id = *reinterpret_cast<const u16*>(log_buffer + temp);
                                u16 digest_size = 0;
                                bool alg_found = false;
                                for (size_t j = 0; j < alg_count; ++j) {
                                    if (alg_sizes[j].alg_id == alg_id) {
                                        digest_size = alg_sizes[j].digest_size;
                                        alg_found = true;
                                        break;
                                    }
                                }
                                if (!alg_found || digest_size == 0) {
                                    alg_error = true;
                                    break;
                                }
                                if (log_size - temp - 2 < digest_size) {
                                    alg_error = true;
                                    break;
                                }
                                temp += static_cast<unsigned long long>(2) + digest_size;
                            }

                            if (alg_error || temp + 4 > log_size) {
                                parse_error = true;
                                break;
                            }
                            const u32 event_size = *reinterpret_cast<const u32*>(log_buffer + temp);

                            if (event_size > log_size - temp - 4) {
                                parse_error = true;
                                break;
                            }
                            const u8* const event_data = log_buffer + temp + 4;
                            offset = temp + 4 + event_size;

                            if (scan_targets(pcr, event_size, event_data)) {
                                found_hyperv = true;
                                break;
                            }
                        }
                        else {
                            if (offset + 32 > log_size) {
                                parse_error = true;
                                break;
                            }
                            const u32 pcr = *reinterpret_cast<const u32*>(log_buffer + offset);
                            const u32 event_size = *reinterpret_cast<const u32*>(log_buffer + offset + 28);

                            if (event_size > log_size - offset - 32) {
                                parse_error = true;
                                break;
                            }
                            const u8* const event_data = log_buffer + offset + 32;
                            offset += 32 + static_cast<unsigned long long>(event_size);

                            if (scan_targets(pcr, event_size, event_data)) {
                                found_hyperv = true;
                                break;
                            }
                        }
                    }
                } while (false);

                delete[] log_buffer;

                if (parse_error) {
                    return true;
                }

                return found_hyperv;
            };

            const char* enlightenment_str = cpu::cpu_manufacturer(cpu::leaf::hv_enlightenment);
            if (enlightenment_str && string::find(enlightenment_str, "KVM")) {
                vma_debug("HYPER-X: Detected Hyper-V enlightenments");
                core::add(brand_enum::QEMU_KVM_HYPERV);
                memo::hyperx::store(HYPERV_ENLIGHTENMENT);
                return HYPERV_ENLIGHTENMENT;
            }

            hyperx_state state = HYPERV_UNKNOWN;

            if (is_hyperv_nested()) {                            
                vma_debug("HYPER-X: Detected Hyper-V in nested state");
                state = HYPERV_NESTED_VM;
            }
            else {
                if (!is_root_partition()) {
                    if (eax() == 11 && is_hyperv_present()) {
                        vma_debug("HYPER-X: Detected Hyper-V guest VM");
                        core::add(brand_enum::HYPERV);
                        state = HYPERV_REAL_VM;
                    }
                    else {
                        vma_debug("HYPER-X: Hyper-V is not active");
                        state = HYPERV_UNKNOWN;
                    }
                }
                else {
                    /* If we reach here, we do some sanity checks to ensure a hypervisor is not trying to spoof itself as Hyper-V, attempting to bypass some detections */
                    const char* brand_str = cpu::cpu_manufacturer(cpu::leaf::hypervisor);
                    bool is_hyper_v_host = (enlightenment_str && strcmp(brand_str, "Microsoft Hv") == 0);

                    if (util::is_windows_11()) {
                        const bool hal = is_halh_present();
                        vma_debug("HYPER-X: Hypervisor Hardware Abstraction Layer: ", hal);
                        is_hyper_v_host &= hal;
                    }

                    const bool tpml = is_log_present();
                    vma_debug("HYPER-X: Hypervisor Measured Boot Log: ", tpml);
                    is_hyper_v_host &= tpml;

                    if (is_hyper_v_host) {
                        vma_debug("HYPER-X: Detected Hyper-V host machine");
                        core::add(brand_enum::HYPERV_ROOT);
                        state = HYPERV_HOST;
                    }
                    else {
                        vma_debug("HYPER-X: Detected hypervisor trying to spoof itself as Hyper-V");
                        core::add(brand_enum::NULL_BRAND, 150);
                        state = HYPERV_SPOOFED;
                    }               
                }
            }

            memo::hyperx::store(state);
            return state;
        #endif
        }

    #if (VMAWARE_WINDOWS)
        [[nodiscard]] static bool is_windows_11() noexcept {
            const HMODULE ntdll = memory::get_module(true);
            if (!ntdll) {
                return false;
            }

            const char* function_names[] = { "RtlGetVersion" };
            void* functions[ARRAYSIZE(function_names)] = {};
            memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

            using rtl_get_version_fn = NTSTATUS(__stdcall*)(PRTL_OSVERSIONINFOW);
            const auto rtl_get_version = reinterpret_cast<rtl_get_version_fn>(functions[0]);
            if (!rtl_get_version) {
                return false;
            }

            RTL_OSVERSIONINFOW vi{};
            vi.dwOSVersionInfoSize = sizeof(vi);

            return rtl_get_version(&vi) == 0 && vi.dwBuildNumber >= 22000;
        }

        [[nodiscard]] static bool is_windows_8_or_newer() noexcept {
            const HMODULE ntdll = memory::get_module(true);
            if (!ntdll) {
                return false;
            }

            const char* function_names[] = { "RtlGetVersion" };
            void* functions[ARRAYSIZE(function_names)] = {};
            memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

            using rtl_get_version_fn = NTSTATUS(__stdcall*)(PRTL_OSVERSIONINFOW);
            const auto rtl_get_version = reinterpret_cast<rtl_get_version_fn>(functions[0]);
            if (!rtl_get_version) {
                return false;
            }

            RTL_OSVERSIONINFOW vi{};
            vi.dwOSVersionInfoSize = sizeof(vi);

            return (rtl_get_version(&vi) == 0 && (vi.dwMajorVersion > 6 || (vi.dwMajorVersion == 6 && vi.dwMinorVersion >= 2)));
        }

        [[nodiscard]] static bool is_32bit_execution_disabled() noexcept {
        #if (VMAWARE_X86_64)
            wchar_t wow64_dir[MAX_PATH] = { 0 };
            const UINT ret = GetSystemWow64DirectoryW(wow64_dir, MAX_PATH);
            if (ret == 0) {
                const DWORD err = GetLastError();
                if (err == ERROR_CALL_NOT_IMPLEMENTED || err == ERROR_PATH_NOT_FOUND) {
                    return true; 
                }
                return true;
            }
            return false;
        #else
            return false;
        #endif
        }

        [[nodiscard]] static bool get_manufacturer_model(const char** out_manufacturer, const char** out_model) noexcept {
            if (out_manufacturer) {
                *out_manufacturer = "";
            }
            if (out_model) {
                *out_model = "";
            }

            if (memo::bios_info::is_cached()) {
                const char* man = memo::bios_info::fetch_manufacturer();
                const char* mod = memo::bios_info::fetch_model();

                if (out_manufacturer) {
                    *out_manufacturer = man;
                }
                if (out_model) {
                    *out_model = mod;
                }

                return (man && man[0] != '\0') || (mod && mod[0] != '\0');
            }

            auto is_placeholder = [](const char* s) noexcept -> bool {
                if (!s || !*s) {
                    return true;
                }

                return 
                    string::equals_ci(s, "System Product Name") ||
                    string::equals_ci(s, "To Be Filled By O.E.M.") ||
                    string::equals_ci(s, "Default string") ||
                    string::equals_ci(s, "Not Specified") ||
                    string::equals_ci(s, "None");
            };

            auto read_reg_utf8 = [](const wchar_t* value_name, char* out, size_t out_size) noexcept -> bool {
                if (!out || out_size == 0) {
                    return false;
                }

                out[0] = '\0';

                WCHAR wbuf[256]{};
                DWORD cb = sizeof(wbuf);

                const LSTATUS st = RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                    value_name,
                    RRF_RT_REG_SZ,
                    nullptr,
                    wbuf,
                    &cb
                );

                if (st != ERROR_SUCCESS || wbuf[0] == L'\0') {
                    return false;
                }

                const int conv = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    wbuf,
                    -1,
                    out,
                    static_cast<int>(out_size),
                    nullptr,
                    nullptr
                );

                if (conv <= 0) {
                    out[0] = '\0';
                    return false;
                }

                out[out_size - 1] = '\0';
                return true;
            };

            char man_tmp[sizeof(memo::bios_info::manufacturer)]{};
            char model_tmp[sizeof(memo::bios_info::model)]{};

            bool got_any = false;

            /*
             * Manufacturer priority:
             * 1) SystemManufacturer
             * 2) BaseBoardManufacturer
             * 3) BIOS vendor string if needed later
             */
            if (read_reg_utf8(L"SystemManufacturer", man_tmp, sizeof(man_tmp)) &&
                !is_placeholder(man_tmp)) {
                memo::bios_info::store_manufacturer(man_tmp);
                got_any = true;
            }
            else if (read_reg_utf8(L"BaseBoardManufacturer", man_tmp, sizeof(man_tmp)) &&
                !is_placeholder(man_tmp)) {
                memo::bios_info::store_manufacturer(man_tmp);
                got_any = true;
            }
            else {
                memo::bios_info::store_manufacturer("");
            }

            /*
             * Model priority:
             * 1) SystemProductName
             * 2) BaseBoardProduct
             * 3) SystemSKU
             * 4) BaseBoardVersion
             */
            if (read_reg_utf8(L"SystemProductName", model_tmp, sizeof(model_tmp)) &&
                !is_placeholder(model_tmp)) {
                memo::bios_info::store_model(model_tmp);
                got_any = true;
            }
            else if (read_reg_utf8(L"BaseBoardProduct", model_tmp, sizeof(model_tmp)) &&
                !is_placeholder(model_tmp)) {
                memo::bios_info::store_model(model_tmp);
                got_any = true;
            }
            else if (read_reg_utf8(L"SystemSKU", model_tmp, sizeof(model_tmp)) &&
                !is_placeholder(model_tmp)) {
                memo::bios_info::store_model(model_tmp);
                got_any = true;
            }
            else if (read_reg_utf8(L"BaseBoardVersion", model_tmp, sizeof(model_tmp)) &&
                !is_placeholder(model_tmp)) {
                memo::bios_info::store_model(model_tmp);
                got_any = true;
            }
            else {
                memo::bios_info::store_model("");
            }

            memo::bios_info::cached = true;

            if (out_manufacturer) {
                *out_manufacturer = memo::bios_info::fetch_manufacturer();
            }
            if (out_model) {
                *out_model = memo::bios_info::fetch_model();
            }

            return got_any;
        }
    #endif

        struct hash {
            static bool has_sse42() noexcept {
                static const bool supported = []() noexcept -> bool {
                #if (VMAWARE_X86)
                    i32 regs[4];
                    cpu::cpuid(regs, cpu::leaf::features);
                    return (regs[2] & (1 << 20)) != 0;
                #else
                    return false;
                #endif
                }();

                return supported;
            }

            /* Table generator for CRC32-C */
            struct crc32c_table {
                u32 table[256];
                crc32c_table() noexcept {
                    for (u32 i = 0; i < 256; ++i) {
                        u32 c = i;
                        for (int j = 0; j < 8; ++j) {
                            c = (c >> 1) ^ ((c & 1) ? 0x82F63B78u : 0);
                        }
                        table[i] = c;
                    }
                }
            };

            /* Software fallback CRC32-C (Castagnoli) of a block of memory */
            static u32 crc32c_sw(u32 crc, const void* VMAWARE_RESTRICT data, const size_t len) noexcept {
                if (VMAWARE_UNLIKELY(!data || len == 0)) {
                    return crc;
                }

                static const crc32c_table instance;
                const u32* const table = instance.table;
                const u8* const ptr = static_cast<const u8*>(data);

                size_t i = 0;

                while (i + 4 <= len) {
                    crc = (crc >> 8) ^ table[(crc ^ ptr[i]) & 0xFF];
                    crc = (crc >> 8) ^ table[(crc ^ ptr[i + 1]) & 0xFF];
                    crc = (crc >> 8) ^ table[(crc ^ ptr[i + 2]) & 0xFF];
                    crc = (crc >> 8) ^ table[(crc ^ ptr[i + 3]) & 0xFF];
                    i += 4;
                }

                while (i < len) {
                    crc = (crc >> 8) ^ table[(crc ^ ptr[i]) & 0xFF];
                    ++i;
                }

                return crc;
            }

            /* Software fallback CRC32-C for a single byte */
            static VMAWARE_CONSTEXPR u32 crc32c_byte_sw(u32 crc, const char data) noexcept {
                crc ^= static_cast<u8>(data);
                for (int i = 0; i < 8; ++i) {
                    crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                }
                return crc;
            }

            /* Native/SSE4.2 hardware assisted or software CRC32C of a single byte */
       #if (VMAWARE_X86 && (VMAWARE_GCC || VMAWARE_CLANG))
            __attribute__((__target__("sse4.2")))
        #endif
            static u32 crc32c_byte(u32 crc, const char data) noexcept {
                #if (VMAWARE_X86)
                if (has_sse42()) {
                    return _mm_crc32_u8(crc, static_cast<u8>(data));
                }
                #endif
                return crc32c_byte_sw(crc, data);
            }

        #if (VMAWARE_X86 && (VMAWARE_GCC || VMAWARE_CLANG))
            __attribute__((__target__("sse4.2")))
        #endif
            static u32 crc32c(u32 crc, const void* data, const size_t len) noexcept {
                if (!has_sse42()) {
                    return crc32c_sw(crc, data, len);
                }

            #if (VMAWARE_X86)
                const u8* ptr = reinterpret_cast<const u8*>(data);
                size_t i = 0;

            #if (VMAWARE_X86_64)
                const size_t qwords = len >> 3;
                const u64* qptr = reinterpret_cast<const u64*>(data);
                u64 crc64 = crc;

                for (; i < qwords; ++i) {
                    VMAWARE_PREFETCH(&qptr[i + 8], _MM_HINT_T0); /* hardware-level prefetch instructions on CPUs ignore invalid addresses without generating page faults */
                    crc64 = _mm_crc32_u64(crc64, qptr[i]);
                }
                crc = static_cast<u32>(crc64);
                i <<= 3; /* Convert QWord count to bytes */
            #else
                const size_t dwords = len >> 2;
                const u32* dptr = reinterpret_cast<const u32*>(data);

                for (; i < dwords; ++i) {
                    crc = _mm_crc32_u32(crc, dptr[i]);
                }
                i <<= 2; /* Convert DWord count to bytes */
            #endif

                /* Hash any remaining trailing bytes */
                for (; i < len; ++i) {
                    crc = _mm_crc32_u8(crc, ptr[i]);
                }

                return crc;
            #else
                return crc32c_sw(crc, data, len);
            #endif
            }
        };
    };


    struct brands {
        static constexpr const char* NULL_BRAND = "Unknown";
        static constexpr const char* VBOX = "VirtualBox";
        static constexpr const char* VMWARE = "VMware";
        static constexpr const char* VMWARE_EXPRESS = "VMware Express";
        static constexpr const char* VMWARE_ESX = "VMware ESX";
        static constexpr const char* VMWARE_GSX = "VMware GSX";
        static constexpr const char* VMWARE_WORKSTATION = "VMware Workstation";
        static constexpr const char* VMWARE_FUSION = "VMware Fusion";
        static constexpr const char* VMWARE_HARD = "VMware (with VmwareHardenedLoader)";
        static constexpr const char* BHYVE = "bhyve";
        static constexpr const char* KVM = "KVM";
        static constexpr const char* QEMU = "QEMU";
        static constexpr const char* QEMU_KVM = "QEMU+KVM";
        static constexpr const char* KVM_HYPERV = "KVM Hyper-V Enlightenment";
        static constexpr const char* QEMU_KVM_HYPERV = "QEMU+KVM Hyper-V Enlightenment";
        static constexpr const char* HYPERV = "Microsoft Hyper-V";
        static constexpr const char* HYPERV_VPC = "Microsoft Virtual PC/Hyper-V";
        static constexpr const char* PARALLELS = "Parallels";
        static constexpr const char* XEN = "Xen HVM";
        static constexpr const char* ACRN = "ACRN";
        static constexpr const char* QNX = "QNX hypervisor";
        static constexpr const char* HYBRID = "Hybrid Analysis";
        static constexpr const char* SANDBOXIE = "Sandboxie";
        static constexpr const char* DOCKER = "Docker";
        static constexpr const char* WINE = "Wine";
        static constexpr const char* VPC = "Virtual PC";
        static constexpr const char* ANUBIS = "Anubis";
        static constexpr const char* JOEBOX = "JoeBox";
        static constexpr const char* THREATEXPERT = "ThreatExpert";
        static constexpr const char* CWSANDBOX = "CWSandbox";
        static constexpr const char* COMODO = "Comodo";
        static constexpr const char* BOCHS = "Bochs";
        static constexpr const char* NVMM = "NetBSD NVMM";
        static constexpr const char* BSD_VMM = "OpenBSD VMM";
        static constexpr const char* INTEL_HAXM = "Intel HAXM";
        static constexpr const char* UNISYS = "Unisys s-Par";
        static constexpr const char* LMHS = "Lockheed Martin LMHS";
        static constexpr const char* CUCKOO = "Cuckoo";
        static constexpr const char* BLUESTACKS = "BlueStacks";
        static constexpr const char* JAILHOUSE = "Jailhouse";
        static constexpr const char* APPLE_VZ = "Apple VZ";
        static constexpr const char* INTEL_KGT = "Intel KGT (Trusty)";
        static constexpr const char* AZURE_HYPERV = "Microsoft Azure Hyper-V";
        static constexpr const char* SIMPLEVISOR = "SimpleVisor";
        static constexpr const char* HYPERV_ROOT = "Hyper-V root partition (host system)";
        static constexpr const char* UML = "User-mode Linux";
        static constexpr const char* POWERVM = "IBM PowerVM";
        static constexpr const char* GCE = "Google Compute Engine (KVM)";
        static constexpr const char* OPENSTACK = "OpenStack (KVM)";
        static constexpr const char* KUBEVIRT = "KubeVirt (KVM)";
        static constexpr const char* AWS_NITRO = "AWS Nitro System EC2 (KVM-based)";
        static constexpr const char* PODMAN = "Podman";
        static constexpr const char* WSL = "WSL";
        static constexpr const char* OPENVZ = "OpenVZ";
        static constexpr const char* BAREVISOR = "Barevisor";
        static constexpr const char* HYPERPLATFORM = "HyperPlatform";
        static constexpr const char* MINIVISOR = "MiniVisor";
        static constexpr const char* INTEL_TDX = "Intel TDX";
        static constexpr const char* LKVM = "LKVM";
        static constexpr const char* AMD_SEV = "AMD SEV";
        static constexpr const char* AMD_SEV_ES = "AMD SEV-ES";
        static constexpr const char* AMD_SEV_SNP = "AMD SEV-SNP";
        static constexpr const char* NEKO_PROJECT = "Neko Project II";
        static constexpr const char* NOIRVISOR = "NoirVisor";
        static constexpr const char* QIHOO = "Qihoo 360 Sandbox";
        static constexpr const char* DBVM = "Dark Byte's VM";
        static constexpr const char* UTM = "UTM";
        static constexpr const char* COMPAQ = "Compaq FX!32";
        static constexpr const char* INSIGNIA = "Insignia RealPC";
        static constexpr const char* CONNECTIX = "Connectix Virtual PC";
        static constexpr const char* CONTAINERD = "Containerd";

        static brand_list_t brand_list(const flagset& flags) {
            if (memo::brand_list::is_cached(flags)) {
                return memo::brand_list::fetch();
            }

            /* Run all the techniques */
            const u16 score = core::run_all(flags);

            brand_list_t active_brands = {};
            active_brands.reserve(MAX_BRANDS);

            for (size_t i = 0; i < MAX_BRANDS; ++i) {
                if (core::brand_scoreboard.at(i).score > 0) {
                    active_brands.emplace_back(std::make_pair(core::brand_scoreboard.at(i).name, core::brand_scoreboard.at(i).score));
                }
            }

            /* Simple helper lambda for early filtering */
            auto remove = [&](const enum brand_enum brand) noexcept {
                for (auto it = active_brands.begin(); it != active_brands.end(); ++it) {
                    if (it->first == brand) {
                        active_brands.erase(it);
                        return;
                    }
                }
            };

            /* If all brands have a point of 0, return "Unknown" */
            if (active_brands.empty()) {
                active_brands.emplace_back(brand_enum::NULL_BRAND, 0);
                memo::brand_list::store(active_brands, flags);
                return active_brands;
            }

            /* If there's only a single brand, return it immediately */
            if (active_brands.size() == 1) {
                const enum brand_enum brand = active_brands.front().first;

                if (brand == brand_enum::HYPERV_ROOT && score > 0) {
                    active_brands.emplace_back(brand_enum::NULL_BRAND, 0);
                    remove(brand_enum::HYPERV_ROOT);
                }

                memo::brand_list::store(active_brands, flags);
                return active_brands;
            }

            /* Remove Hyper-V artifacts and Unknown if found alongside other brands */
            if (active_brands.size() > 1) {
                remove(brand_enum::HYPERV_ROOT);
                remove(brand_enum::NULL_BRAND);
            }

            /* If filtering emptied the vector, fall back to NULL_BRAND */
            if (active_brands.empty()) {
                active_brands.emplace_back(brand_enum::NULL_BRAND, 0);
            }

            /* Capture initial hit presence */
            std::bitset<MAX_BRANDS> brand_hits = {};
            for (const auto& brand : active_brands) {
                brand_hits.set(static_cast<u8>(brand.first));
            }

            struct rule {
                brand_enum a;
                brand_enum b;
                brand_enum c; /* brand_enum::NULL_BRAND if unused (double merge) */
                brand_enum result;
            };

            static constexpr rule merge_rules[] = {
                /* Double merges */
                { brand_enum::VPC, brand_enum::HYPERV, brand_enum::NULL_BRAND, brand_enum::HYPERV_VPC },

                { brand_enum::AZURE_HYPERV, brand_enum::HYPERV, brand_enum::NULL_BRAND, brand_enum::AZURE_HYPERV },
                { brand_enum::AZURE_HYPERV, brand_enum::VPC, brand_enum::NULL_BRAND, brand_enum::AZURE_HYPERV },
                { brand_enum::AZURE_HYPERV, brand_enum::HYPERV_VPC, brand_enum::NULL_BRAND, brand_enum::AZURE_HYPERV },

                { brand_enum::QEMU, brand_enum::KVM, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM },
                { brand_enum::KVM, brand_enum::HYPERV, brand_enum::NULL_BRAND, brand_enum::KVM_HYPERV },
                { brand_enum::QEMU, brand_enum::HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },
                { brand_enum::QEMU_KVM, brand_enum::HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },

                { brand_enum::KVM, brand_enum::HYPERV_VPC, brand_enum::NULL_BRAND, brand_enum::KVM_HYPERV },
                { brand_enum::QEMU, brand_enum::HYPERV_VPC, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },
                { brand_enum::QEMU_KVM, brand_enum::HYPERV_VPC, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },

                { brand_enum::KVM, brand_enum::KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::KVM_HYPERV },
                { brand_enum::QEMU, brand_enum::KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },
                { brand_enum::QEMU_KVM, brand_enum::KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },

                { brand_enum::HYPERV_VPC, brand_enum::KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::KVM_HYPERV },
                { brand_enum::HYPERV, brand_enum::KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::KVM_HYPERV },
                { brand_enum::HYPERV_VPC, brand_enum::QEMU_KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },
                { brand_enum::HYPERV, brand_enum::QEMU_KVM_HYPERV, brand_enum::NULL_BRAND, brand_enum::QEMU_KVM_HYPERV },

                /* Triple merge (retains third brand) */
                { brand_enum::QEMU, brand_enum::KVM, brand_enum::KVM_HYPERV, brand_enum::QEMU_KVM_HYPERV },

                /* VMware merges */
                { brand_enum::VMWARE, brand_enum::VMWARE_FUSION, brand_enum::NULL_BRAND, brand_enum::VMWARE_FUSION },
                { brand_enum::VMWARE, brand_enum::VMWARE_EXPRESS, brand_enum::NULL_BRAND, brand_enum::VMWARE_EXPRESS },
                { brand_enum::VMWARE, brand_enum::VMWARE_ESX, brand_enum::NULL_BRAND, brand_enum::VMWARE_ESX },
                { brand_enum::VMWARE, brand_enum::VMWARE_GSX, brand_enum::NULL_BRAND, brand_enum::VMWARE_GSX },
                { brand_enum::VMWARE, brand_enum::VMWARE_WORKSTATION, brand_enum::NULL_BRAND, brand_enum::VMWARE_WORKSTATION },

                { brand_enum::VMWARE_HARD, brand_enum::VMWARE, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD },
                { brand_enum::VMWARE_HARD, brand_enum::VMWARE_FUSION, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD },
                { brand_enum::VMWARE_HARD, brand_enum::VMWARE_EXPRESS, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD },
                { brand_enum::VMWARE_HARD, brand_enum::VMWARE_ESX, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD },
                { brand_enum::VMWARE_HARD, brand_enum::VMWARE_GSX, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD },
                { brand_enum::VMWARE_HARD, brand_enum::VMWARE_WORKSTATION, brand_enum::NULL_BRAND, brand_enum::VMWARE_HARD }
            };

            std::bitset<MAX_BRANDS> current_active = brand_hits;
            std::array<brand_score_t, MAX_BRANDS> active_scores{};

            for (const auto& brand : active_brands) {
                active_scores[static_cast<u8>(brand.first)] = brand.second;
            }

            /* Evaluate merge rules */
            for (const auto& rule : merge_rules) {
                const u8 a_idx = static_cast<u8>(rule.a);
                const u8 b_idx = static_cast<u8>(rule.b);
                const u8 c_idx = static_cast<u8>(rule.c);
                const u8 res_idx = static_cast<u8>(rule.result);

                const bool a_hit = brand_hits.test(a_idx);
                const bool b_hit = brand_hits.test(b_idx);

                const bool c_hit = (rule.c == brand_enum::NULL_BRAND) || brand_hits.test(c_idx);

                if (a_hit && b_hit && c_hit) {
                    current_active.reset(a_idx);
                    current_active.reset(b_idx);
                    if (rule.c != brand_enum::NULL_BRAND) {
                        current_active.reset(c_idx);
                    }
                    current_active.set(res_idx);
                    active_scores[res_idx] = 2; /* default merged score assignment */
                }
            }

            /* Reconstruct active list */
            active_brands.clear();
            for (size_t i = 0; i < MAX_BRANDS; ++i) {
                if (current_active.test(i)) {
                    active_brands.emplace_back(static_cast<brand_enum>(i), active_scores[i]);
                }
            }

            if (active_brands.size() > 1) {
                std::sort(active_brands.begin(), active_brands.begin() + static_cast<std::ptrdiff_t>(active_brands.size()), [](
                    const brand_element_t& a,
                    const brand_element_t& b
                ) {
                    return a.second > b.second; /* .second is brand score */  
                } );
            }

            memo::brand_list::store(active_brands, flags);
            return active_brands;
        }

        static VMAWARE_CONSTEXPR const char* brand_enum_to_string(const brand_enum brand) noexcept {
            switch (brand) {
                case brand_enum::VBOX:                  return VM::brands::VBOX;
                case brand_enum::VMWARE:                return VM::brands::VMWARE;
                case brand_enum::VMWARE_EXPRESS:        return VM::brands::VMWARE_EXPRESS;
                case brand_enum::VMWARE_ESX:            return VM::brands::VMWARE_ESX;
                case brand_enum::VMWARE_GSX:            return VM::brands::VMWARE_GSX;
                case brand_enum::VMWARE_WORKSTATION:    return VM::brands::VMWARE_WORKSTATION;
                case brand_enum::VMWARE_FUSION:         return VM::brands::VMWARE_FUSION;
                case brand_enum::VMWARE_HARD:           return VM::brands::VMWARE_HARD;
                case brand_enum::BHYVE:                 return VM::brands::BHYVE;
                case brand_enum::KVM:                   return VM::brands::KVM;
                case brand_enum::QEMU:                  return VM::brands::QEMU;
                case brand_enum::QEMU_KVM:              return VM::brands::QEMU_KVM;
                case brand_enum::KVM_HYPERV:            return VM::brands::KVM_HYPERV;
                case brand_enum::QEMU_KVM_HYPERV:       return VM::brands::QEMU_KVM_HYPERV;
                case brand_enum::HYPERV:                return VM::brands::HYPERV;
                case brand_enum::HYPERV_VPC:            return VM::brands::HYPERV_VPC;
                case brand_enum::PARALLELS:             return VM::brands::PARALLELS;
                case brand_enum::XEN:                   return VM::brands::XEN;
                case brand_enum::ACRN:                  return VM::brands::ACRN;
                case brand_enum::QNX:                   return VM::brands::QNX;
                case brand_enum::HYBRID:                return VM::brands::HYBRID;
                case brand_enum::SANDBOXIE:             return VM::brands::SANDBOXIE;
                case brand_enum::DOCKER:                return VM::brands::DOCKER;
                case brand_enum::WINE:                  return VM::brands::WINE;
                case brand_enum::VPC:                   return VM::brands::VPC;
                case brand_enum::ANUBIS:                return VM::brands::ANUBIS;
                case brand_enum::JOEBOX:                return VM::brands::JOEBOX;
                case brand_enum::THREATEXPERT:          return VM::brands::THREATEXPERT;
                case brand_enum::CWSANDBOX:             return VM::brands::CWSANDBOX;
                case brand_enum::COMODO:                return VM::brands::COMODO;
                case brand_enum::BOCHS:                 return VM::brands::BOCHS;
                case brand_enum::NVMM:                  return VM::brands::NVMM;
                case brand_enum::BSD_VMM:               return VM::brands::BSD_VMM;
                case brand_enum::INTEL_HAXM:            return VM::brands::INTEL_HAXM;
                case brand_enum::UNISYS:                return VM::brands::UNISYS;
                case brand_enum::LMHS:                  return VM::brands::LMHS;
                case brand_enum::CUCKOO:                return VM::brands::CUCKOO;
                case brand_enum::BLUESTACKS:            return VM::brands::BLUESTACKS;
                case brand_enum::JAILHOUSE:             return VM::brands::JAILHOUSE;
                case brand_enum::APPLE_VZ:              return VM::brands::APPLE_VZ;
                case brand_enum::INTEL_KGT:             return VM::brands::INTEL_KGT;
                case brand_enum::AZURE_HYPERV:          return VM::brands::AZURE_HYPERV;
                case brand_enum::SIMPLEVISOR:           return VM::brands::SIMPLEVISOR;
                case brand_enum::HYPERV_ROOT:           return VM::brands::HYPERV_ROOT;
                case brand_enum::UML:                   return VM::brands::UML;
                case brand_enum::POWERVM:               return VM::brands::POWERVM;
                case brand_enum::GCE:                   return VM::brands::GCE;
                case brand_enum::OPENSTACK:             return VM::brands::OPENSTACK;
                case brand_enum::KUBEVIRT:              return VM::brands::KUBEVIRT;
                case brand_enum::AWS_NITRO:             return VM::brands::AWS_NITRO;
                case brand_enum::PODMAN:                return VM::brands::PODMAN;
                case brand_enum::WSL:                   return VM::brands::WSL;
                case brand_enum::OPENVZ:                return VM::brands::OPENVZ;
                case brand_enum::BAREVISOR:             return VM::brands::BAREVISOR;
                case brand_enum::HYPERPLATFORM:         return VM::brands::HYPERPLATFORM;
                case brand_enum::MINIVISOR:             return VM::brands::MINIVISOR;
                case brand_enum::INTEL_TDX:             return VM::brands::INTEL_TDX;
                case brand_enum::LKVM:                  return VM::brands::LKVM;
                case brand_enum::AMD_SEV:               return VM::brands::AMD_SEV;
                case brand_enum::AMD_SEV_ES:            return VM::brands::AMD_SEV_ES;
                case brand_enum::AMD_SEV_SNP:           return VM::brands::AMD_SEV_SNP;
                case brand_enum::NEKO_PROJECT:          return VM::brands::NEKO_PROJECT;
                case brand_enum::NOIRVISOR:             return VM::brands::NOIRVISOR;
                case brand_enum::QIHOO:                 return VM::brands::QIHOO;
                case brand_enum::DBVM:                  return VM::brands::DBVM;
                case brand_enum::UTM:                   return VM::brands::UTM;
                case brand_enum::COMPAQ:                return VM::brands::COMPAQ;
                case brand_enum::INSIGNIA:              return VM::brands::INSIGNIA;
                case brand_enum::CONNECTIX:             return VM::brands::CONNECTIX;
                case brand_enum::CONTAINERD:            return VM::brands::CONTAINERD;
                /* do not modify placement of NULL_BRAND, it's used as an anchor point to count the number of brands */
                case brand_enum::NULL_BRAND:            return VM::brands::NULL_BRAND;
            }

            return "Invalid";
        }
        
        static std::string brand_multiple(const brand_list_t& list) {
            /* VMAWARE_ASSUME(!list.empty()); */
            std::string buffer = {};
            buffer += brands::brand_enum_to_string(list[0].first);

            for (size_t i = 1; i < list.size(); i++) {
                buffer += " or ";
                buffer += brands::brand_enum_to_string(list[i].first);
            }

            return buffer;
        }

        static std::string brand_multiple(const flagset& flags = core::generate_default()) {
            if (memo::multi_brand::is_cached(flags)) {
                return memo::multi_brand::fetch();
            }

            const brand_list_t& list = brands::brand_list(flags);
            const std::string& buffer = brand_multiple(list);

            memo::multi_brand::store(buffer, flags);
            return buffer;
        }

        static enum brand_enum brand_single(const brand_list_t& list) noexcept {
            /* VMAWARE_ASSUME(!list.empty()); */
            const brand_element_t brand = list.front();
            return brand.first;
        }

        static brand_enum brand_single(const flagset& flags = core::generate_default()) {
            if (memo::single_brand::is_cached(flags)) {
                return memo::single_brand::fetch();
            }

            const brand_list_t& list = brands::brand_list(flags);
            const enum brand_enum brand = brand_single(list);

            memo::single_brand::store(brand, flags);

            return brand;
        }
    };

// START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS

#if (VMAWARE_MSVC)
    #pragma region "x86"
#endif

#if 1 /* meant for closing this whole section in the IDE */
    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 and 0x40000000-0x40000100
     * @category x86
     * @implements VM::VMID
     */
     [[nodiscard]] static bool vmid() {
    #if (!VMAWARE_X86)
        return false;
    #else
         return (
             cpu::vmid_template(cpu::leaf::basic_info) ||
             cpu::vmid_template(cpu::leaf::hypervisor) ||
             cpu::vmid_template(cpu::leaf::hv_enlightenment)
         );
    #endif
    }


    /**
     * @brief Check if CPU brand model contains any VM-specific string snippets
     * @category x86
     * @implements VM::CPU_BRAND
     */
     [[nodiscard]] static bool cpu_brand() {
     #if (!VMAWARE_X86)
         return false;
     #else
         const char* brand = cpu::get_brand();

         if (!brand) {
             return false;
         }

         if (string::starts_with(brand, "QEMU Virtual CPU version")) {
             return core::add(brand_enum::QEMU);
         }

         struct check_t {
             const char* text;
             brand_enum brand;
         };

         static constexpr check_t checks[] = {
             { "qemu",       brand_enum::QEMU },
             { "kvm",        brand_enum::KVM },
             { "vbox",       brand_enum::VBOX },
             { "virtualbox", brand_enum::VBOX },
             { "bhyve",      brand_enum::BHYVE },
             { "parallels",  brand_enum::PARALLELS }
         };

         for (const auto& c : checks) {
             if (string::find(brand, c.text)) {
                 vma_debug("CPU_BRAND: match = ", c.text);
                 return core::add(c.brand);
             }
         }

         if (
             string::find(brand, "monitor")    ||
             string::find(brand, "hypervisor") ||
             string::find(brand, "hvisor")
            )
         {
             vma_debug("CPU_BRAND: generic virtualization match");
             return true;
         }

         return false;
     #endif
     }


    /**
     * @brief Check if hypervisor feature bit in CPUID ECX bit 31 is enabled
     * @category x86
     * @implements VM::HYPERVISOR_BIT
     */
    [[nodiscard]] static bool hypervisor_bit() {
    #if (!VMAWARE_X86)
        return false;
    #else
        u32 eax = 0;
        u32 ebx = 0; 
        u32 ecx = 0; 
        u32 edx = 0;

        cpu::cpuid(eax, ebx, ecx, edx, cpu::leaf::features);
        constexpr u32 HYPERVISOR_MASK = (1u << 31);
        const hyperx_state state = util::hyper_x();

        if (ecx & HYPERVISOR_MASK) {
            /* If hypervisor bit is enabled, but we're in a root partition, prevent it from flagging */
            if (state == HYPERV_HOST) {
                return false;
            }

            return true;
        }

        /* If hypervisor bit is disabled, but VMAware detects Hyper-V signals, we're in an impossible situation (patching) */
        if (state == HYPERV_HOST) {
            return true;
        }

        return false;
    #endif
    }


    /**
     * @brief Check for hypervisor brand string length
     * @category x86
     * @implements VM::HYPERVISOR_STR
     */
    [[nodiscard]] static bool hypervisor_str() {
    #if (!VMAWARE_X86)
        return false;
    #else
        if (util::hyper_x() == HYPERV_HOST) {
            return false;
        }

        char out[(sizeof(i32) * 4) + 1] = { 0 }; /* e*x size + number of e*x registers + null terminator */
        cpu::cpuid(reinterpret_cast<int*>(out), cpu::leaf::hypervisor);

        vma_debug("HYPERVISOR_STR: eax: ", static_cast<u32>(out[0]),
            ", ebx: ", static_cast<u32>(out[1]),
            ", ecx: ", static_cast<u32>(out[2]),
            ", edx: ", static_cast<u32>(out[3])
        );

        return (strlen(out + 4) >= 4);
    #endif  
    }
    

    /**
     * @brief Check for various Bochs-related emulation oversights through CPU checks
     * @category x86
     * @author Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
     * @implements VM::BOCHS_CPU
     */
    [[nodiscard]] static bool bochs_cpu() {
    #if (!VMAWARE_X86)
        return false;
    #else
        const bool intel = cpu::is_intel();
        const bool amd = cpu::is_amd();

        if (!(intel || amd)) {
            vma_debug("BOCHS_CPU: neither AMD or Intel detected, returned false");
            return false;
        }

        const char* brand = cpu::get_brand();

        if (intel) {
            /* Technique 1: not a valid brand */
            if (strcmp(brand, "              Intel(R) Pentium(R) 4 CPU        ") == 0) {
                vma_debug("BOCHS_CPU: technique 1 found");
                return core::add(brand_enum::BOCHS);
            }
        } else if (amd) {
            /* Technique 2: "processor" should have a capital P */
            if (strcmp(brand, "AMD Athlon(tm) processor") == 0) {
                vma_debug("BOCHS_CPU: technique 2 found");
                return core::add(brand_enum::BOCHS);
            }

            /* Technique 3: Check for absence of AMD easter egg for K7 and K8 CPUs */
            if (!cpu::is_leaf_supported(cpu::leaf::amd_easter_egg)) {
                return false;
            }

            u32 unused = 0;
            u32 eax = 0;
            cpu::cpuid(eax, unused, unused, unused, cpu::leaf::features);

            auto is_k7 = [](const u32 eax) noexcept -> bool {
                if ((eax & 0x0FF00F00) != 0x00000600) {
                    return false;
                }

                const u32 model = (eax >> 4) & 0xF;

                return (model - 1) < 4;
            };

            auto is_k8 = [](const u32 eax) noexcept -> bool {
                if (((eax >> 8) & 0xF) != 0xF) {
                    return false;
                }

                const u32 extended_family = (eax >> 20) & 0xFF;

                return extended_family <= 1;
            };

            if (!(is_k7(eax) || is_k8(eax))) {
                return false;
            }

            u32 ecx_bochs = 0;
            cpu::cpuid(unused, unused, ecx_bochs, unused, cpu::leaf::amd_easter_egg);

            if (ecx_bochs == 0) {
                return true;
            }
        }

        return false;
    #endif
    }
       
    
    /**
	 * @brief Check if the system's thread count matches the expected thread count for the detected CPU model
     * @category x86
     * @implements VM::THREAD_MISMATCH
     */
    [[nodiscard]] static bool thread_mismatch() {
    #if (!VMAWARE_X86)
        return false;
    #else
        auto is_smt_active = []() noexcept -> bool {
        #if (VMAWARE_WINDOWS)
            DWORD len = 0;

            if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len) ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                return false;
            }

            unsigned char* buf = nullptr;
            bool result = false;

            /* To support CPU hot-plugging */
            while (true) {
                buf = static_cast<unsigned char*>(_aligned_malloc(len, alignof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)));
                if (!buf) {
                    return false;
                }

                if (GetLogicalProcessorInformationEx(
                    RelationProcessorCore,
                    reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf),
                    &len)) {
                    break;
                }

                _aligned_free(buf);
                buf = nullptr;

                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    return false;
                }
            }

            size_t offset = 0;
            while (offset < len) {
                auto* rec = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buf + offset);

                if (rec->Size == 0 || offset + rec->Size > len) {
                    break;
                }

                if (rec->Relationship == RelationProcessorCore) {
                    const PROCESSOR_RELATIONSHIP& pr = rec->Processor;
                    unsigned logicals = 0;

                    for (WORD i = 0; i < pr.GroupCount; ++i) {
                        logicals += util::popcount(static_cast<unsigned long long>(pr.GroupMask[i].Mask));
                    }

                    if (logicals > 1) {
                        result = true;
                        break;
                    }
                }

                offset += rec->Size; 
            }

            _aligned_free(buf);
            return result;

        #elif (VMAWARE_APPLE)

            int logical = 0, physical = 0;
            size_t sz = sizeof(logical);

            if (sysctlbyname("hw.logicalcpu", &logical, &sz, nullptr, 0) != 0) {
                return false;
            }

            sz = sizeof(physical);
            if (sysctlbyname("hw.physicalcpu", &physical, &sz, nullptr, 0) != 0) {
                return false;
            }

            return logical > physical;

        #else

            {
                std::ifstream f("/sys/devices/system/cpu/smt/control");
                if (f) {
                    std::string s;
                    if (std::getline(f, s)) {
                        string::trim_inplace(s);

                        if (s == "on") {
                            return true;
                        }

                        if (s == "off" || s == "forceoff" || s == "notsupported") {
                            return false;
                        }
                    }
                }
            }

            {
                std::ifstream f("/sys/devices/system/cpu/smt/active");
                if (f) {
                    std::string s;
                    if (std::getline(f, s)) {
                        string::trim_inplace(s);

                        if (s == "1") {
                            return true;
                        }

                        if (s == "0") {
                            return false;
                        }
                    }
                }
            }

            {
                std::ifstream f("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list");
                if (f) {
                    std::string s;
                    if (std::getline(f, s)) {
                        string::trim_inplace(s);

                        for (char ch : s) {
                            if (ch == ',' || ch == '-') {
                                return true;
                            }
                        }
                    }
                }
            }

            {
                std::ifstream cpuinfo("/proc/cpuinfo");
                if (cpuinfo) {
                    std::string line;
                    int siblings = -1;
                    int cores = -1;

                    while (std::getline(cpuinfo, line)) {
                        if (line.empty()) {
                            break;
                        }

                        auto pos = line.find(':');
                        if (pos == std::string::npos) {
                            continue;
                        }

                        std::string key = line.substr(0, pos);
                        std::string val = line.substr(pos + 1);

                        string::trim_inplace(key);
                        string::trim_inplace(val);

                        if (key == "siblings") {
                            try { siblings = std::stoi(val); }
                            catch (...) {}
                        }
                        else if (key == "cpu cores") {
                            try { cores = std::stoi(val); }
                            catch (...) {}
                        }
                    }

                    if (siblings > cores && siblings > 0 && cores > 0) {
                        return true;
                    }
                }
            }

            return false;
        #endif
        };

    #if (VMAWARE_WINDOWS && defined VMAWARE_DEBUG)
        const char* manufacturer = "";
        const char* device_model = "";
        if (util::get_manufacturer_model(&manufacturer, &device_model)) {
            vma_debug("{\"manufacturer\": \"", manufacturer, "\", \"model\": \"", device_model, "\"}");
        }
    #endif

        constexpr size_t max_model_len = 32;
        cpu::cpu_type type = cpu::cpu_type::UNKNOWN;
        size_t db_size = 0;
        const cpu::cpu_entry* db = nullptr;
        const cpu::cpu_entry* matched = nullptr;
        const char* model_name = nullptr;

        if (cpu::is_intel()) {
            const cpu::model_struct model = cpu::get_model();
            if (model.found) {
                model_name = model.string;

                if (strstr(model_name, "Ultra") != nullptr) {
                    type = cpu::cpu_type::INTEL_ULTRA;
                    cpu::get_intel_ultra_db(db, db_size);
                }
                else if (model.is_i_series) {
                    type = cpu::cpu_type::INTEL_I;
                    cpu::get_intel_core_db(db, db_size);
                }
                else if (model.is_xeon) {
                    type = cpu::cpu_type::INTEL_XEON;
                    cpu::get_intel_xeon_db(db, db_size);
                }
            }
        }
        else if (cpu::is_amd()) {
            type = cpu::cpu_type::AMD;
            model_name = cpu::get_brand();
            cpu::get_amd_ryzen_db(db, db_size);
        }

        if (model_name != nullptr && db != nullptr && model_name[0] != '\0') {
            const char* str = model_name;

            for (size_t i = 0; str[i] != '\0'; ) {
                const char c = str[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                    i++;
                    continue;
                }

                u32 current_hash = 0;
                size_t current_len = 0;
                size_t j = i;

                while (true) {
                    char k = str[j];
                    const bool is_valid = 
                        (k >= '0' && k <= '9') ||
                        (k >= 'A' && k <= 'Z') ||
                        (k >= 'a' && k <= 'z') ||
                        (k == '-');

                    if (!is_valid) {
                        break;
                    }

                    if (current_len >= max_model_len) {
                        while (str[j] != '\0' && str[j] != ' ') {
                            j++;
                        }
                        break;
                    }

                    if (type == cpu::cpu_type::AMD && (k >= 'A' && k <= 'Z')) {
                        k += 32;
                    }

                    current_hash = util::hash::crc32c_byte(current_hash, k);
                    current_len++;
                    j++;

                    const char next = str[j];
                    const bool next_is_alnum = 
                        (next >= '0' && next <= '9') ||
                        (next >= 'A' && next <= 'Z') ||
                        (next >= 'a' && next <= 'z');

                    if (!next_is_alnum) {
                        for (size_t idx = 0; idx < db_size; ++idx) {
                            if (db[idx].hash == current_hash) {
                                if (matched == nullptr || current_len > 0) {
                                    matched = &db[idx];
                                }
                            }
                        }
                    }
                }

                i = j;
            }
        }

        if (matched == nullptr) {
            return false;
        }

        vma_debug("CPU model = ", model_name);

        const u32 actual = memo::thread_count::fetch();
        const bool model_expects_smt = matched->smt;

        if (!model_expects_smt) {
            if (is_smt_active()) {
                vma_debug("THREAD_MISMATCH: CPU normally runs under SMT, but SMT was fully disabled on BIOS");
                return false;
            }
        }

        if (actual != matched->threads) {
            vma_debug("THREAD_MISMATCH: Current threads -> ", actual);
            vma_debug("THREAD_MISMATCH: Expected threads -> ", matched->threads);
            return true;
        }

        return false;
    #endif
    }


    /**
     * @brief Check for CPUID signatures that reveal the presence of a hypervisor
     * @category x86
     * @implements VM::CPUID_SIGNATURE
     */
    [[nodiscard]] static bool cpuid_signature() {
    #if (!VMAWARE_X86)
        return false;
    #else
        u32 eax = 0;
        u32 ebx = 0;
        u32 ecx = 0;
        u32 edx = 0;
        cpu::cpuid(eax, ebx, ecx, edx, cpu::leaf::hv_interface);

        constexpr u32 simplevisor = 0x00766853; /* " vhS" */

        vma_debug("CPUID_SIGNATURE: eax = ", std::hex, eax);

        if (eax == simplevisor) {
            return core::add(brand_enum::SIMPLEVISOR);
        }

        if (cpu::is_intel()) {
            const bool has_leaf_b = cpu::is_leaf_supported(cpu::leaf::ext_topology);
            const bool has_leaf_1f = cpu::is_leaf_supported(cpu::leaf::v2_ext_topology);

            /* If neither extended topology leaf is supported, we can't perform the check */
            if (!has_leaf_b && !has_leaf_1f) {
                return false;
            }

            u32 l1_eax = 0;
            u32 l1_ebx = 0; 
            u32 l1_ecx = 0; 
            u32 l1_edx = 0;
            
            u32 vb_eax = 0;
            u32 vb_ebx = 0; 
            u32 vb_ecx = 0; 
            u32 vb_edx = 0;
            
            u32 v1f_eax = 0;
            u32 v1f_ebx = 0; 
            u32 v1f_ecx = 0; 
            u32 v1f_edx = 0;

            u32 aba_start = 0;
            u32 aba_end = 0;

            u32 unused = 0;
            int retries = 0;

            /*
             * Triple-read ABA pattern to detect thread migration and bounded to 8 retries
             * leaf 1's Initial APIC ID is the ABA guard
             */
            for (;;) {
                cpu::cpuid(l1_eax, l1_ebx, l1_ecx, l1_edx, cpu::leaf::features, 0);
                aba_start = (l1_ebx >> 24) & 0xFF; /* Initial APIC ID */

                if (has_leaf_b) {
                    cpu::cpuid(vb_eax, vb_ebx, vb_ecx, vb_edx, cpu::leaf::ext_topology, 0);
                }

                if (has_leaf_1f) {
                    cpu::cpuid(v1f_eax, v1f_ebx, v1f_ecx, v1f_edx, cpu::leaf::v2_ext_topology, 0);
                }

                cpu::cpuid(unused, l1_ebx, unused, unused, cpu::leaf::features, 0);
                aba_end = (l1_ebx >> 24) & 0xFF;

                if (aba_start == aba_end || ++retries >= 8) { 
                    break; 
                }
            }

            /*
             * If we hit the retry limit and the thread is still migrating,
             * abort the check to prevent false positives
             */
            if (aba_start != aba_end) {
                return false;
            }

            const u32 initial_apic_id = aba_start;

            /* Check Leaf 0x0B against Leaf 1 */
            if (has_leaf_b) {
                const u32 vb_level = (vb_ecx >> 8) & 0xFF;

                if (vb_level != 0) {
                    /* If x2APIC ID is < 255, Initial APIC ID must match exactly */
                    if (vb_edx < 255 && (vb_edx & 0xFF) != initial_apic_id) {
                        return true;
                    }
                }
            }

            /* Check Leaf 0x1F against Leaf 1, and cross-check with 0x0B */
            if (has_leaf_1f) {
                const u32 v1f_level = (v1f_ecx >> 8) & 0xFF;

                if (v1f_level != 0) {
                    /* If x2APIC ID is < 255, Initial APIC ID must match exactly */
                    if (v1f_edx < 255 && (v1f_edx & 0xFF) != initial_apic_id) {
                        return true;
                    }

                    /* Cross-check 0x0B vs 0x1F if both are supported and valid */
                    if (has_leaf_b) {
                        const u32 vb_level = (vb_ecx >> 8) & 0xFF;
                        if (vb_level != 0 && vb_edx != v1f_edx) {
                            return true;
                        }
                    }
                }
            }
        }
        else if (cpu::is_amd()) {
            const bool has_leaf_7 = cpu::is_leaf_supported(cpu::leaf::ext_features);

            if (!has_leaf_7) {
                return false;
            }

            u32 l7_eax = 0;
            u32 l7_ebx = 0;
            u32 l7_ecx = 0;
            u32 l7_edx = 0;
            cpu::cpuid(l7_eax, l7_ebx, l7_ecx, l7_edx, cpu::leaf::ext_features, 0);

            /*
             * Intel enumerates hardware mitigations in Leaf 7.0.EDX:
             * Bit 26: IBRS and IBPB
             * Bit 27: STIBP
             * Bit 31: SSBD
             *
             * AMD processors strictly reserve these bits (force them to 0)
             * and instead enumerate their mitigations in Leaf 0x80000008.EBX
             */
            const bool has_intel_ibrs = (l7_edx & (1 << 26)) != 0;
            const bool has_intel_stibp = (l7_edx & (1 << 27)) != 0;
            const bool has_intel_ssbd = (l7_edx & (1 << 31)) != 0;

            if (has_intel_ibrs || has_intel_stibp || has_intel_ssbd) {
                return true;
            }
        }

        return false;
    #endif
    }
                
                
    /**
     * @brief Check for Intel KGT (Trusty branch) hypervisor signature in CPUID
     * @link https://github.com/intel/ikgt-core/blob/7dfd4d1614d788ec43b02602cce7a272ef8d5931/vmm/vmexit/vmexit_cpuid.c
     * @category x86
     * @implements VM::KGT_SIGNATURE
     */
    [[nodiscard]] static bool intel_kgt_signature() {
    #if (!VMAWARE_X86)
        return false;
    #else
        u32 unused = 0;
        u32 ecx = 0; 
        u32 edx = 0;
        cpu::cpuid(unused, unused, ecx, edx, cpu::leaf::hv_privileges);

        constexpr u32 ECX_SIG = 0x4D4D5645u; /* 'EVMM' */
        constexpr u32 EDX_SIG = 0x43544E49u; /* 'INTC' */

        if (ecx == ECX_SIG && edx == EDX_SIG) {
            return core::add(brand_enum::INTEL_KGT);
        }

        return false;
    #endif
    }


    /**
     * @brief Check for hypervisor overhead by measuring instruction and exception latency
     * @category Windows, x86
     * @implements VM::TIMER
     */
    [[nodiscard]] static bool timer() VMAWARE_SERIALIZE {
    #if (VMAWARE_X86 && VMAWARE_WINDOWS)
        if (util::is_x86_process_on_arm()) {
            vma_debug("TIMER: Running inside a binary translation layer");
            return false;
        }

        /* Calculation of minimum threshold for instrution latency */
        double threshold = 2.5;
        if (util::hyper_x() == HYPERV_HOST) {
            vma_debug("TIMER: Hyper-V detected, running nested checks");
            threshold = 100.0;
        }

        static timer::cache_state state;
        static_assert(alignof(timer::cache_state) >= 64, "timer::cache_state must be aligned to 64 bytes to prevent cache-line thrashing (false sharing).");
        static_assert(std::is_standard_layout<timer::cache_state>::value, "timer::cache_state must be standard layout for predictable memory offsets.");

        state.counter = 0;
        state.start_test.store(false, std::memory_order_relaxed);
        state.test_done.store(false, std::memory_order_relaxed);

        bool hypervisor_detected = false;
        static HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);
        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        const GROUP_AFFINITY trigger_affinity = timer::scheduler::get_mask(true);
        static GROUP_AFFINITY counter_affinity = timer::scheduler::get_mask(false);

        if (!trigger_affinity.Mask || !counter_affinity.Mask) {
            return false;
        }

        /* Our software clock */
        auto counter_thread = []() noexcept -> void {
            SetThreadGroupAffinity(current_thread, &counter_affinity, nullptr);
            SetThreadPriority(current_thread, THREAD_PRIORITY_HIGHEST); /* decrease chance of being rescheduled */
            SetThreadPriorityBoost(current_thread, TRUE); /* disable dynamic boosts */

            timer::timer_tick_t local_counter = state.counter;

            /* better than calling incq in inline asm, as this forces standard increment cache behavior */
            #define TICK8() \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter; \
                local_counter++; state.counter = local_counter;

            #define TICK64() \
                TICK8(); TICK8(); TICK8(); TICK8(); \
                TICK8(); TICK8(); TICK8(); TICK8();

            #define TICK512() \
                TICK64(); TICK64(); TICK64(); TICK64(); \
                TICK64(); TICK64(); TICK64(); TICK64();

            while (!state.start_test.load(std::memory_order_acquire)) {}

            while (!state.test_done.load(std::memory_order_relaxed)) {
                TICK512(); TICK512(); TICK512(); TICK512();
                TICK512(); TICK512(); TICK512(); TICK512();
            }
            #undef TICK512
            #undef TICK64
            #undef TICK8
        };

        bool serialize_available = cpu::is_intel();
        if (serialize_available) {
            /* SERIALIZE requires Ice Lake or newer */
            u32 l7_eax = 0, l7_ebx = 0, l7_ecx = 0, l7_edx = 0;
            cpu::cpuid(l7_eax, l7_ebx, l7_ecx, l7_edx, cpu::leaf::ext_features, 0);
            if (!(l7_edx & (1u << 14))) {
                serialize_available = false;
            }
        }

        /* Prepare threads for check */
        vma_debug("TIMER: CPU supports SERIALIZE: ", serialize_available);
        GROUP_AFFINITY old_affinity{};
        const DWORD old_process_priority = GetPriorityClass(current_process);
        const int old_thread_priority = GetThreadPriority(current_thread);
        SetThreadGroupAffinity(current_thread, &trigger_affinity, &old_affinity);
        SetPriorityClass(current_process, ABOVE_NORMAL_PRIORITY_CLASS); /* ABOVE_NORMAL_PRIORITY_CLASS + THREAD_PRIORITY_HIGHEST = 12 base priority */
        SetThreadPriority(current_thread, THREAD_PRIORITY_HIGHEST);
        SetThreadPriorityBoost(current_thread, TRUE); /* disable dynamic thread priority adjustments by Windows, not turbo boosts by the hardware itself */

        VMAWARE_CONSTEXPR const u32 ct_seed = timer::config::get_seed();
        const size_t batch_size = timer::config::generate_batch_size(ct_seed);

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = {
            "ZwRaiseException"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using zw_raise_exception_fn = NTSTATUS(__stdcall*)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
        zw_raise_exception_fn zw_raise_exception = reinterpret_cast<zw_raise_exception_fn>(functions[0]);
        if (!zw_raise_exception) {
            return false;
        }

        std::vector<timer::timer_tick_t> vm_samples(batch_size), ref_samples(batch_size); /* pre page-fault MMU, we won't warm-up cpuid samples for the P-states intentionally */
        std::vector<timer::timer_tick_t> api_samples(batch_size), db_samples(batch_size);

        /* Lock the memory for the samples to prevent soft #PF during timing if permissions are enough */
        const bool vm_samples_locked = VirtualLock(vm_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        const bool ref_samples_locked = VirtualLock(ref_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        const bool api_samples_locked = VirtualLock(api_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        const bool db_samples_locked = VirtualLock(db_samples.data(), batch_size * sizeof(timer::timer_tick_t));

        /* Independent multi-trial state initialization */
        constexpr int trials = 5;
        constexpr size_t local_max_attempts = 1000 * trials;
        timer::timer_tick_t best_cpuid_l = (std::numeric_limits<timer::timer_tick_t>::max)();
        timer::timer_tick_t best_ref_l = (std::numeric_limits<timer::timer_tick_t>::max)();
        timer::timer_tick_t best_api_l = (std::numeric_limits<timer::timer_tick_t>::max)();
        timer::timer_tick_t best_db_l = (std::numeric_limits<timer::timer_tick_t>::max)();

        /* To isolate the SEH frame from C++ unwinding scopes */
        struct exception_handler {
            static VMAWARE_NOINLINE void execute_db() noexcept {
                __try {
                #if (VMAWARE_MSVC)
                    const auto eflags = __readeflags();
                    __writeeflags(eflags | 0x100);
                    __nop();
                #elif (VMAWARE_X86_64)
                    __asm__ volatile (
                        "pushfq \n\t"
                        "orq $0x100, (%%rsp) \n\t"
                        "popfq \n\t"
                        "nop \n\t"
                        :
                    :
                        : "cc", "memory"
                    );
                    #else
                    __asm__ volatile (
                        "pushfl \n\t"
                        "orl $0x100, (%%esp) \n\t"
                        "popfl \n\t"
                        "nop \n\t"
                        :
                    :
                        : "cc", "memory"
                    );
                #endif
                }
                __except (
                    GetExceptionCode() == EXCEPTION_SINGLE_STEP
                    ? (GetExceptionInformation()->ContextRecord->EFlags &= ~0x100U, EXCEPTION_CONTINUE_EXECUTION)
                    : EXCEPTION_CONTINUE_SEARCH
                    ) {
                }
            }

            /* decltype to resolve the local function pointer type without template keywords */
            static VMAWARE_NO_CFG void nt_raise_exception(
                decltype(zw_raise_exception) zw_raise,
                EXCEPTION_RECORD* er,
                CONTEXT* ctx,
                volatile bool* flag
            ) noexcept {
                __try {
                #if (VMAWARE_X86_64)
                    RtlCaptureContext(ctx);
                #else
                    /* On x86_32, RtlCaptureContext is unreliable under clang-cl with FPO */
                    ctx->ContextFlags = CONTEXT_CONTROL;
                    uintptr_t current_esp = 0;
                    uintptr_t current_ebp = 0;
                    uintptr_t current_eip = 0;
                    u32 current_cs = 0;
                    u32 current_ss = 0;
                    u32 current_eflags = 0;

                #if (VMAWARE_MSVC) /* This matches clang-cl on purpose */
                    __asm {
                        mov current_esp, esp
                        mov current_ebp, ebp

                        xor eax, eax
                        mov ax, cs
                        mov current_cs, eax

                        xor eax, eax
                        mov ax, ss
                        mov current_ss, eax

                        call get_eip
                        get_eip :
                        pop eax
                            mov current_eip, eax
                    }
                    current_eflags = static_cast<u32>(__readeflags());
                #else
                    __asm__ volatile(
                        "movl %%esp, %0 \n\t"
                        "movl %%ebp, %1 \n\t"
                        "mov %%cs, %2 \n\t"
                        "mov %%ss, %3 \n\t"
                        "pushfl \n\t"
                        "popl %4 \n\t"
                        "call 1f \n\t"
                        "1: \n\t"
                        "popl %5 \n\t"
                        : "=r"(current_esp), "=r"(current_ebp), "=r"(current_cs), "=r"(current_ss), "=r"(current_eflags), "=r"(current_eip)
                    );
                #endif

                    ctx->Esp = current_esp;
                    ctx->Ebp = current_ebp;
                    ctx->Eip = current_eip;
                    ctx->SegCs = current_cs;
                    ctx->SegSs = current_ss;
                    ctx->EFlags = current_eflags;
                #endif
                    * flag = true;
                    zw_raise(er, ctx, 1);
                }
                __except (
                    GetExceptionCode() == EXCEPTION_SINGLE_STEP
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH
                    ) {
                }
            }
        };

        std::thread t1(counter_thread);
        state.start_test.store(true, std::memory_order_release);

        /* Cache and CPU scheduler warm-up won't affect anything in the measurement loop, so ramp up frequency/P-states to a high non-AVX Turbo/P-state without vmexits */
        timer::engine::warmup_cpu(serialize_available);

        for (int trial = 0; trial < trials; ++trial) {
            size_t valid = 0;
            size_t invalid = 0;

            /*
             * state is a static local variable, so accessing state.counter directly requires the compiler to resolve its address using RIP-relative addressing or base-plus-displacement addressing on every single iteration
             * depending on the compiler's O level and the presence of PIC/PIE, this can introduce small addressing calculations inside the loop, so by assigning the address to a local pointer outside the loop,
             * we encourage the compiler to load this absolute pointer into a CPU register BEFORE the loop starts so at the end it translates to a simple mov
            */
            volatile timer::timer_tick_t* const counter_ptr = &state.counter;

            /* Inside the timing windows, there must be zero memory output (no stack arrays can be written to), zero conditional branches and zero stack spilling (no register push/pops) */
            if (serialize_available) {
                while (valid < batch_size && invalid < local_max_attempts) {
                    /* cpuid and serialize/lfence interpolated so that any turbo boost, thermal throttling, speculation (for the loop overhead itself, not for the serializing instructions), etc affects samples equally */
                    timer::timer_tick_t r_pre, r_post, v_pre, v_post, sync;

                    /* This is done as a counter to both legitimate and malicious hypervisors interrupts that may pause the counter thread while we measure */
                    sync = *counter_ptr;
                    while (*counter_ptr == sync); /* infer if counter got enough quantum momentum (so its currently scheduled) */

                    /*
                     * SERIALIZE/LFENCE check is before CPUID on purpose, so that possible pauses when cpuid is executed do not affect SERIALIZE/LFENCE too. The hv needs to wait for cpuid to pause the thread
                     * the amount of instructions (8 in case of LFENCE) are enough for the Cross-Core/Cross-CCD MESI RFO cache bounce in the data race so that the counter thread sees an increment
                     */
                    sync = *counter_ptr;
                    VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                    while (*counter_ptr == sync); /* fastest busy-waiting strategy, PAUSE can conditionally exit, calling APIs like SwitchToThread() would be even worse */

                    r_pre = *counter_ptr;
                    std::atomic_signal_fence(std::memory_order_acq_rel);
                    _serialize();
                    std::atomic_signal_fence(std::memory_order_acq_rel);
                    r_post = *counter_ptr;

                    sync = *counter_ptr;
                    while (*counter_ptr == sync); /* sync to our counter tick again by spam hitting L3 */
                    sync = *counter_ptr;
                    VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                    while (*counter_ptr == sync); /* and again */

                    v_pre = *counter_ptr;
                    std::atomic_signal_fence(std::memory_order_seq_cst); /* _ReadWriteBarrier() aka dont emit runtime fences */
                #if (VMAWARE_GCC || VMAWARE_CLANG)  
                    size_t a = 0;
                    size_t b = 0, c = 0, d = 0;
                    __asm__ volatile (
                        "cpuid"
                        : "+a"(a), "=b"(b), "=c"(c), "=d"(d)
                    );
                #else
                    int dummy[4];
                    __cpuid(dummy, 0);
                #endif
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                    v_post = *counter_ptr;

                    /* We dont filter by cycles spent here (for example by querying thread cycle time) because the kernel would use TSC and the point of this function is to not use TSC or any other clock */
                    if (v_post > v_pre && r_post > r_pre) {
                        vm_samples[valid] = v_post - v_pre;
                        ref_samples[valid] = r_post - r_pre;
                        valid++;
                    }
                    else {
                        invalid++;
                    }

                    /* Burn cycles executing a random number of instructions in each loop iteration, so that the hypervisor doesn't know when to pause the counter thread */
                    timer::engine::burn_random_cycles(ct_seed, v_post, r_post);
                }
            }
            else {
                while (valid < batch_size && invalid < local_max_attempts) {
                    /* This block's logic is the same as above but using LFENCE instead of SERIALIZE, read code comments above */
                    timer::timer_tick_t r_pre, r_post, v_pre, v_post, sync;

                    sync = *counter_ptr;
                    while (*counter_ptr == sync);
                    sync = *counter_ptr;
                    VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                    while (*counter_ptr == sync);

                    r_pre = *counter_ptr;
                    std::atomic_signal_fence(std::memory_order_acq_rel);
                    _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
                    _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
                    std::atomic_signal_fence(std::memory_order_acq_rel);
                    r_post = *counter_ptr;

                    sync = *counter_ptr;
                    while (*counter_ptr == sync);
                    sync = *counter_ptr;
                    VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                    while (*counter_ptr == sync);

                    v_pre = *counter_ptr;
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                #if (VMAWARE_GCC || VMAWARE_CLANG)
                    size_t a = 0;
                    size_t b = 0, c = 0, d = 0;
                    __asm__ volatile (
                        "cpuid"
                        : "+a"(a), "=b"(b), "=c"(c), "=d"(d)
                    );
                #else
                    int dummy[4];
                    __cpuid(dummy, 0);
                #endif
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                    v_post = *counter_ptr;

                    if (v_post > v_pre && r_post > r_pre) {
                        vm_samples[valid] = v_post - v_pre;
                        ref_samples[valid] = r_post - r_pre;
                        valid++;
                    }
                    else {
                        invalid++;
                    }

                    timer::engine::burn_random_cycles(ct_seed, v_post, r_post);
                }
            }

            if (valid > 0) {
                /* Discard the unused default-initialized zero-elements */
                std::vector<timer::timer_tick_t> active_vm_samples(vm_samples.begin(), vm_samples.begin() + valid);
                std::vector<timer::timer_tick_t> active_ref_samples(ref_samples.begin(), ref_samples.begin() + valid);

                /* Check for lowest dense cluster with no interrupt spikes, filter noise we can't directly detect (SMIs, NMIs, etc) */
                const timer::timer_tick_t cpuid_l = timer::engine::calculate_latency(active_vm_samples);
                const timer::timer_tick_t ref_l = timer::engine::calculate_latency(active_ref_samples);

                /* Record the cleanest/lowest latency observed across the independent trials */
                if (cpuid_l < best_cpuid_l) {
                    best_cpuid_l = cpuid_l;
                }
                if (ref_l < best_ref_l) {
                    best_ref_l = ref_l;
                }
            }

            valid = 0;
            invalid = 0;

            /* 
             * I choose #DB because it forces a L0 to L1 nested vmexit when Hyper-V is running
             * L0 must sync the exception bitmap with L1 in order for this to receive pending events, as the CPU always jumps to the hv running on the metal
             * VMCB/VMCS public dumps shows Hyper-V intercepts #DB, #AC and #MC
             */
            while (valid < batch_size && invalid < local_max_attempts) {
                timer::timer_tick_t db_pre, db_post, api_pre, api_post, sync;

                sync = *counter_ptr;
                while (*counter_ptr == sync);
                sync = *counter_ptr;
                VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                while (*counter_ptr == sync);

                db_pre = *counter_ptr;
                std::atomic_signal_fence(std::memory_order_acq_rel);
                exception_handler::execute_db();
                std::atomic_signal_fence(std::memory_order_acq_rel);
                db_post = *counter_ptr;

                sync = *counter_ptr;
                while (*counter_ptr == sync);
                sync = *counter_ptr;
                VMAWARE_PREFETCH(counter_ptr, _MM_HINT_T0);
                while (*counter_ptr == sync);

                volatile bool flag = false;
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_FULL;

                EXCEPTION_RECORD er{};
                er.ExceptionCode = EXCEPTION_SINGLE_STEP;
                er.ExceptionFlags = 0;

                api_pre = *counter_ptr;
                std::atomic_signal_fence(std::memory_order_acq_rel);
                exception_handler::nt_raise_exception(zw_raise_exception, &er, &ctx, &flag);
                std::atomic_signal_fence(std::memory_order_acq_rel);
                api_post = *counter_ptr;

                if (api_post > api_pre && db_post > db_pre) {
                    api_samples[valid] = api_post - api_pre;
                    db_samples[valid] = db_post - db_pre;
                    valid++;
                }
                else {
                    invalid++;
                }

                timer::engine::burn_random_cycles(ct_seed, api_post, db_post);
            }

            if (valid > 0) {
                std::vector<timer::timer_tick_t> active_api_samples(api_samples.begin(), api_samples.begin() + valid);
                std::vector<timer::timer_tick_t> active_db_samples(db_samples.begin(), db_samples.begin() + valid);

                const timer::timer_tick_t api_l = timer::engine::calculate_latency(active_api_samples);
                const timer::timer_tick_t db_l = timer::engine::calculate_latency(active_db_samples);

                if (api_l < best_api_l) {
                    best_api_l = api_l;
                }
                if (db_l < best_db_l) {
                    best_db_l = db_l;
                }
            }
        }

        state.test_done.store(true, std::memory_order_release);
        t1.join();

        constexpr auto uninitialized_tick = (std::numeric_limits<timer::timer_tick_t>::max)();
        const bool invalid_measurement = (best_ref_l == uninitialized_tick && best_cpuid_l == uninitialized_tick) || (best_db_l == uninitialized_tick && best_api_l == uninitialized_tick);

        /* Analyze instruction latency results and report exactly what VMAware found */
        if (!invalid_measurement) {
            /* VMM = Time spent in hypervisor and bare metal; nVMM = Time spent in bare metal */
            const double latency_ratio = best_ref_l ? (double)best_cpuid_l / (double)best_ref_l : 0;
            vma_debug("TIMER: Instruction > VMM -> ", best_cpuid_l, " | nVMM -> ", best_ref_l, " | Ratio -> ", latency_ratio);

            /* High latency can occur even with CPUID interception disabled if vCPU pinning is not 1:1, thus detecting the hypervisor, as this is a cache-based counter */
            if (latency_ratio >= threshold) {
                vma_debug("TIMER: Detected #VMEXIT latency"); 
                hypervisor_detected = true;
            }
            else if (best_cpuid_l >= 12000 || best_ref_l >= 12000) { /* If latency is abnormally high, it means something was spamming interrupts */
                vma_debug("TIMER: Detected artificial IPI delivery to timing threads");
                hypervisor_detected = true;
            }

            const double exception_ratio = best_db_l ? (double)best_db_l / (double)best_api_l : 0.0;
            vma_debug("TIMER: Exception > VMM -> ", best_db_l, " | nVMM -> ", best_api_l, " | Ratio -> ", exception_ratio);

            if (exception_ratio >= 2.5) {
                vma_debug("TIMER: Detected #DB interception latency");
                vma_debug("TIMER: If you have #DB interception disabled, it means you're running under nested");
                hypervisor_detected = true;
            }
        }

        SetThreadPriorityBoost(current_thread, FALSE);
        SetThreadPriority(current_thread, old_thread_priority);
        SetPriorityClass(current_process, old_process_priority);
        SetThreadGroupAffinity(current_thread, &old_affinity, nullptr);
        if (vm_samples_locked) {
            VirtualUnlock(vm_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        }
        if (ref_samples_locked) {
            VirtualUnlock(ref_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        }
        if (api_samples_locked) {
            VirtualUnlock(api_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        }
        if (db_samples_locked) {
            VirtualUnlock(db_samples.data(), batch_size * sizeof(timer::timer_tick_t));
        }

        return hypervisor_detected;
    #endif
        return false;
    }
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
    #pragma region "Linux"
#endif

#if (VMAWARE_LINUX)
    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     * @implements VM::SYSTEMD
     */
    [[nodiscard]] static bool systemd_virt() {
        if (!(util::exists("/usr/bin/systemd-detect-virt") || util::exists("/bin/systemd-detect-virt"))) {
            vma_debug("SYSTEMD: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("systemd-detect-virt");

        if (result == nullptr) {
            vma_debug("SYSTEMD: ", "invalid stdout output from systemd-detect-virt");
            return false;
        }

        vma_debug("SYSTEMD: ", "output = ", *result);

        return (*result != "none");
    }


    /**
     * @brief Check if the chassis vendor is a VM vendor
     * @category Linux
     * @implements VM::CVENDOR
     */
    [[nodiscard]] static bool chassis_vendor() {
        const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

        if (!util::exists(vendor_file)) {
            vma_debug("CVENDOR: ", "file doesn't exist");
            return false;
        }

        const std::string vendor = util::read_file(vendor_file);

        /* TODO: More can definitely be added, only QEMU and VBox were tested so far */
        if (util::find(vendor, "QEMU")) { return core::add(brand_enum::QEMU); }
        if (util::find(vendor, "Oracle Corporation")) { return core::add(brand_enum::VBOX); }

        vma_debug("CVENDOR: vendor = ", vendor);

        return false;
    }


    /**
     * @brief Check if the chassis type is valid
     * @category Linux
     * @implements VM::CTYPE
     */
    [[nodiscard]] static bool chassis_type() {
        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";

        if (util::exists(chassis)) {
            try {
                return (std::stoi(util::read_file(chassis)) == 1);
            }
            catch (...) {
                return false;
            }
        }

        vma_debug("CTYPE: ", "file doesn't exist");

        return false;
    }


    /**
     * @brief Check if /.dockerenv or /.dockerinit file is present
     * @category Linux
     * @implements VM::DOCKERENV
     */
    [[nodiscard]] static bool dockerenv() {
        if (util::exists("/.dockerenv") || util::exists("/.dockerinit")) {
            return core::add(brand_enum::DOCKER);
        }

        return false;
    }


    /**
     * @brief Check if dmidecode output matches a VM brand
     * @category Linux
     * @warning Permissions required
     * @implements VM::DMIDECODE
     */
    [[nodiscard]] static bool dmidecode() {
        if (!util::is_admin()) {
            vma_debug("DMIDECODE: ", "precondition return called (root = ", util::is_admin(), ")");
            return false;
        }

        if (!(util::exists("/bin/dmidecode") || util::exists("/usr/bin/dmidecode"))) {
            vma_debug("DMIDECODE: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

        if (!result || result->empty()) {
            vma_debug("DMIDECODE: ", "invalid output");
            return false;
        }
        
        if (*result == "QEMU") {
            return core::add(brand_enum::QEMU);
        }
        
        if (*result == "VirtualBox") {
            return core::add(brand_enum::VBOX);
        }
        
        if (*result == "KVM") {
            return core::add(brand_enum::KVM);
        } 
        
        if (std::strtol(result->c_str(), nullptr, 10) >= 1) {
            return true;
        }
         
        vma_debug("DMIDECODE: ", "output = ", *result);

        return false;
    }


    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category Linux
     * @implements VM::MAC
     */
    [[nodiscard]] static bool mac_address_check() {
        struct fdguard {
            int fd;
            explicit fdguard(int fd = -1) : fd(fd) {}
            ~fdguard() { 
                if (fd != -1) { 
                    ::close(fd); 
                } 
            }
            int get() const { 
                return fd; 
            }
            int release() { 
                const int tmp = fd; 
                fd = -1; 
                return tmp; 
            }
        };

        u8 mac[6] = { 0 };
        struct ifreq ifr{};
        struct ifconf ifc{};
        char buf[1024];
        int success = 0;

        int const sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) {
            return false;
        }
        const fdguard sock_guard(sock); /* will close on function exit */

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;

        if (ioctl(sock_guard.get(), SIOCGIFCONF, &ifc) == -1) {
            return false;
        }

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it != end; ++it) {
            std::size_t const name_len = std::min<std::size_t>(sizeof(ifr.ifr_name) - 1, strnlen(it->ifr_name, sizeof(it->ifr_name)));
            std::memcpy(ifr.ifr_name, it->ifr_name, name_len);
            *(ifr.ifr_name + name_len) = '\0';

            if (ioctl(sock_guard.get(), SIOCGIFFLAGS, &ifr) != 0) {
                return false;
            }

            if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sock_guard.get(), SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }

        if (success) {
            std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        }
        else {
            vma_debug("MAC: ", "not successful");
        }

    #ifdef VMAWARE_DEBUG
        {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(mac[0]) << ":"
                << static_cast<int>(mac[1]) << ":"
                << static_cast<int>(mac[2]) << ":XX:XX:XX";
            vma_debug("MAC: ", ss.str());
        }
    #endif

        if ((mac[0] | mac[1] | mac[2]) == 0) {
            return false;
        }

        const u32 prefix = static_cast<u32>(mac[0]) | (static_cast<u32>(mac[1]) << 8) | (static_cast<u32>(mac[2]) << 16);

        constexpr u32 VBOX = 0x270008;  /* 08:00:27 */
        constexpr u32 VMW1 = 0x29000C;  /* 00:0C:29 */
        constexpr u32 VMW2 = 0x141C00;  /* 00:1C:14 */
        constexpr u32 VMW3 = 0x565000;  /* 00:50:56 */
        constexpr u32 VMW4 = 0x690500;  /* 00:05:69 */
        constexpr u32 XEN = 0xE31600;   /* 00:16:E3 */
        constexpr u32 PAR = 0x421C00;   /* 00:1C:42 */

        if (prefix == VBOX) {
            return core::add(brand_enum::VBOX);
        }
        
        if (prefix == VMW1 || prefix == VMW2
            || prefix == VMW3 || prefix == VMW4) {
            return core::add(brand_enum::VMWARE);
        }
        
        if (prefix == XEN) {
            return core::add(brand_enum::XEN);
        }
        
        if (prefix == PAR) {
            return core::add(brand_enum::PARALLELS);
        }

        return false;
    }


    /**
     * @brief Check if dmesg output matches a VM brand
     * @category Linux
     * @warning Permissions required
     * @implements VM::DMESG
     */
    [[nodiscard]] static bool dmesg() {
    #if (VMAWARE_CPP <= 11)
        return false;
    #else
        if (!util::is_admin()) {
            return false;
        }

        if (!util::exists("/bin/dmesg") && !util::exists("/usr/bin/dmesg")) {
            vma_debug("DMESG: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"");

        if (!result || result->empty()) {
            return false;
        }
        
        if (*result == "KVM") {
            return core::add(brand_enum::KVM);
        }
        
        if (*result == "QEMU") {
            return core::add(brand_enum::QEMU);
        }
        
        if (std::strtol(result->c_str(), nullptr, 10)) {
            return true;
        }

        vma_debug("DMESG: ", "output = ", *result);

        return false;
    #endif
    }


    /**
     * @brief Check if /sys/class/hwmon/ directory is present. If not, likely a VM
     * @category Linux
     * @implements VM::HWMON
     */
    [[nodiscard]] static bool hwmon() {
        return (!util::exists("/sys/class/hwmon/"));
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     * @implements VM::LINUX_USER_HOST
     */
    [[nodiscard]] static bool linux_user_host() {
        if (util::is_admin()) {
            return false;
        }

        const char* username = std::getenv("USER");
        const char* hostname = std::getenv("HOSTNAME");

        if (!username || !hostname) {
            vma_debug("VM::LINUX_USER_HOST: environment variables not found");
            return false;
        }

        vma_debug("LINUX_USER_HOST: user = ", username);
        vma_debug("LINUX_USER_HOST: host = ", hostname);

        return (
            (strcmp(username, "liveuser") == 0) &&
            (strcmp(hostname, "localhost-live") == 0)
        );
    }


    /**
     * @brief Check for the presence of BlueStacks-specific folders
     * @category ARM, Linux
     * @implements VM::BLUESTACKS_FOLDERS
     */
    [[nodiscard]] static bool bluestacks() {
    #if (!VMAWARE_ARM)
        return false;
    #else
        if (
            util::exists("/mnt/windows/BstSharedFolder") ||
            util::exists("/sdcard/windows/BstSharedFolder")
        ) {
            return core::add(brand_enum::BLUESTACKS);
        }

        return false;
    #endif
    }


    /**
	 * @brief Check for AMD-SEV MSR running on the system
	 * @category x86, Linux, MacOS
     * @warning Permissions required
     * @implements VM::AMD_SEV_MSR
	 */
	[[nodiscard]] static bool amd_sev_msr() {
    #if (VMAWARE_X86 && (VMAWARE_LINUX || VMAWARE_APPLE))
        if (!cpu::is_amd()) {
            return false;
        }

        if (!util::is_admin()) {
            return false;
        }

        constexpr u32 msr_index = 0xc0010131;

        if (!cpu::is_leaf_supported(cpu::leaf::encrypted_mem)) {
            return false;
        }

        u32 eax = 0;
        u32 unused = 0;

        cpu::cpuid(eax, unused, unused, unused, cpu::leaf::encrypted_mem);

        if (!(eax & (1 << 1))) {
            return false;
        }

        u64 result = 0;

        const std::string msr_device = "/dev/cpu/0/msr";
        std::ifstream msr_file(msr_device, std::ios::binary);

        if (!msr_file.is_open()) {
            vma_debug("AMD_SEV: unable to open MSR file");
            return false;
        }

        msr_file.seekg(msr_index);
        msr_file.read(reinterpret_cast<char*>(&result), sizeof(result));

        if (!msr_file) {
            vma_debug("AMD_SEV: unable to open MSR file");
            return false;
        }

        if (result & (static_cast<u64>(1) << 2)) { 
            return core::add(brand_enum::AMD_SEV_SNP); 
        }
        if (result & (static_cast<u64>(1) << 1)) { 
            return core::add(brand_enum::AMD_SEV_ES); 
        }
        if (result & 1) { 
            return core::add(brand_enum::AMD_SEV);
        }

        return false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory
     * @category Linux
     * @implements VM::QEMU_VIRTUAL_DMI
     */
    [[nodiscard]] static bool qemu_virtual_dmi() {
        const char* sys_vendor = "/sys/devices/virtual/dmi/id/sys_vendor";
        const char* modalias = "/sys/devices/virtual/dmi/id/modalias";

        if (util::exists(sys_vendor) && util::exists(modalias)) {
            const std::string sys_vendor_str = util::read_file(sys_vendor);
            const std::string modalias_str = util::read_file(modalias);

            if (util::find(sys_vendor_str, "QEMU") && util::find(modalias_str, "QEMU")) {
                return core::add(brand_enum::QEMU);
            }
        }

        return false;
    }


    /**
     * @brief Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory
     * @category Linux
     * @warning Permissions required
     * @implements VM::QEMU_USB
     */
    [[nodiscard]] static bool qemu_usb() {
        if (!util::is_admin()) {
            return false;
        }

        constexpr const char* usb_path = "/sys/kernel/debug/usb/devices";

        std::ifstream file(usb_path);
        if (!file) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.find("QEMU") != std::string::npos) {
                return true;
            }
        }

        return false;
    }


    /**
     * @brief Check for presence of any files in /sys/hypervisor directory
     * @category Linux
     * @implements VM::HYPERVISOR_DIR
     */
    [[nodiscard]] static bool hypervisor_dir() {
        struct DirDeleter {
            void operator()(DIR* d) const {
                if (d != nullptr) {
                    closedir(d);
                }
            }
        };

        std::unique_ptr<DIR, DirDeleter> dir(opendir("/sys/hypervisor"));

        if (dir == nullptr) {
            return false;
        }

        const struct dirent* entry{};
        int count = 0;

        while ((entry = readdir(dir.get())) != nullptr) {
            if (
                (entry->d_name[0] == '.' && entry->d_name[1] == '\0') ||
                (entry->d_name[1] == '.' && entry->d_name[2] == '\0')
               ) 
            {
                continue;
            }

            count++;
            break;
        }

        dir.reset();

        bool type = false;

        if (util::exists("/sys/hypervisor/type")) {
            type = true;
        }

        if (type) {
            const std::string content = util::read_file("/sys/hypervisor/type");
            if (util::find(content, "xen")) {
                return core::add(brand_enum::XEN);
            }
        }

        /* Check if there's a few files in that directory */
        return ((count != 0) && type);
    }


    /**
     * @brief Check for the "UML" string in the CPU brand
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::UML_CPU
     */
    [[nodiscard]] static bool uml_cpu() {
        /* Method 1, get the CPU brand model */
        const std::string brand = cpu::get_brand();

        if (brand == "UML") {
            return core::add(brand_enum::UML);
        }

        /* Method 2, match for the "User Mode Linux" string in /proc/cpuinfo */
        const char* file = "/proc/cpuinfo";

        if (util::exists(file)) {
            const std::string file_content = util::read_file(file);

            if (util::find(file_content, "User Mode Linux")) {
                return core::add(brand_enum::UML);
            }
        }

        return false;
    } 


    /**
     * @brief Check for any indications of hypervisors in the kernel message logs
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @warning Permissions required
     * @implements VM::KMSG
     */
    [[nodiscard]] static bool kmsg() {
        if (!util::is_admin()) {
            return false;
        }

        const int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            vma_debug("KMSG: Failed to open /dev/kmsg");
            return false;
        }

        char buffer[1024] = {};
        std::stringstream ss;
        int empty_reads = 0;
        constexpr int MAX_EMPTY_READS = 10;

        while (true) {
            const ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);

            if (bytes_read > 0) {
                *(buffer + bytes_read) = '\0';
                ss << buffer;
                empty_reads = 0; 
            }
            else if (bytes_read == 0) {
                if (++empty_reads >= MAX_EMPTY_READS) {
                    vma_debug("KMSG: Reached maximum empty reads (EOF), breaking.");
                    break;
                }
                usleep(10000); /* Sleep for 10 milliseconds */
            }
            else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (++empty_reads >= MAX_EMPTY_READS) {
                        vma_debug("KMSG: Reached maximum EAGAIN retries, breaking.");
                        break;
                    }
                    usleep(10000);
                }
                else {
                    vma_debug("KMSG: Error reading /dev/kmsg, errno = ", errno);
                    break;
                }
            }
        }

        close(fd);

        const std::string content = ss.str();

        if (content.empty()) {
            return false;
        }

        return (util::find(content, "Hypervisor detected"));
    }


    /**
     * @brief Check for a VBox kernel module
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::VBOX_MODULE
     */
    [[nodiscard]] static bool vbox_module() {
        const char* file = "/proc/modules";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "vboxguest")) {
            return core::add(brand_enum::VBOX);
        }

        return false;
    }


    /**
     * @brief Check for potential VM info in /proc/sysinfo
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::SYSINFO_PROC
     */
    [[nodiscard]] static bool sysinfo_proc() {
        const char* file = "/proc/sysinfo";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "VM00")) {
            return true;
        }

        return false;
    } 


    /**
     * @brief Check for string matches of VM brands in the linux DMI
     * @category Linux
     * @implements VM::DMI_SCAN
     */
    [[nodiscard]] static bool dmi_scan() {
        /*
         *  cat: /sys/class/dmi/id/board_serial:   Permission denied
         *  cat: /sys/class/dmi/id/chassis_serial: Permission denied
         *  cat: /sys/class/dmi/id/product_serial: Permission denied
         *  cat: /sys/class/dmi/id/product_uuid:   Permission denied
         */

        constexpr std::array<const char*, 7> dmi_array{
            "/sys/class/dmi/id/bios_vendor",
            "/sys/class/dmi/id/board_name",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/chassis_asset_tag",
            "/sys/class/dmi/id/product_family",
            "/sys/class/dmi/id/product_sku",
            "/sys/class/dmi/id/sys_vendor"
        };

        constexpr std::array<std::pair<const char*, enum brand_enum>, 15> vm_table{ {
            { "kvm", brand_enum::KVM },
            { "openstack", brand_enum::OPENSTACK },
            { "kubevirt", brand_enum::KUBEVIRT },
            { "amazon ec2", brand_enum::AWS_NITRO },
            { "qemu", brand_enum::QEMU },
            { "vmware", brand_enum::VMWARE },
            { "innotek gmbh", brand_enum::VBOX },
            { "virtualbox", brand_enum::VBOX },
            { "oracle corporation", brand_enum::VBOX },
            { "bochs", brand_enum::BOCHS },
            { "parallels", brand_enum::PARALLELS },
            { "bhyve", brand_enum::BHYVE },
            { "hyper-v", brand_enum::HYPERV },
            { "apple virtualization", brand_enum::APPLE_VZ },
            { "google compute engine", brand_enum::GCE }
        } };


        for (const auto file : dmi_array) {
            if (!util::exists(file)) {
                continue;
            }

            std::string content = util::read_file(file);
            if (content.empty()) {
                continue;
            }

            string::to_lower_inplace(content);

            for (const auto& vm_string : vm_table) {
                if (string::contains(content, vm_string.first)) {
                    vma_debug("DMI_SCAN: content = ", content);

                    if (vm_string.second == brand_enum::AWS_NITRO) {
                        if (smbios_vm_bit()) {
                            return core::add(brand_enum::AWS_NITRO);
                        }
                    }
                    else {
                        return core::add(vm_string.second);
                    }
                }
            }
        }

        return false;
    }


    /**
     * @brief Check for the VM bit in the SMBIOS data
     * @category Linux
     * @warning Permissions required
     * @implements VM::SMBIOS_VM_BIT
     */
    [[nodiscard]] static bool smbios_vm_bit() {
        if (!util::is_admin()) {
            return false;
        }

        const char* file = "/sys/firmware/dmi/entries/0-0/raw";

        if (!util::exists(file)) {
            return false;
        }

        const std::vector<u8> content = util::read_file_binary(file);

        if (content.size() < 20 || content.at(1) < 20) {
            vma_debug("SMBIOS_VM_BIT: ", "only read ", content.size(), " bytes, expected 20");
            return false;
        }

        vma_debug("SMBIOS_VM_BIT: ", "content.at(19) = ", static_cast<int>(content.at(19)));

        return (content.at(19) & (1 << 4));
    } 


    /**
     * @brief Check for podman file in /run/
     * @category Linux
     * @implements VM::PODMAN_FILE
     */
    [[nodiscard]] static bool podman_file() {
        if (util::exists("/run/.containerenv")) {
            return core::add(brand_enum::PODMAN);
        }

        return false;
    }


    /**
     * @brief Check for WSL or microsoft indications in /proc/ subdirectories
     * @category Linux
     * @implements VM::WSL_PROC
     */
    [[nodiscard]] static bool wsl_proc_subdir() {
        auto read_proc_nonblock = [](const char* path) -> std::string {
            const int fd = open(path, O_RDONLY | O_NONBLOCK);

            if (fd < 0) {
                return "";
            }

            char buf[512] = {};
            const ssize_t n = read(fd, buf, sizeof(buf) - 1);

            close(fd);

            if (n <= 0) {
                return "";
            }

            return { buf, static_cast<size_t>(n) };
        };

        const std::string osrelease = read_proc_nonblock("/proc/sys/kernel/osrelease");
        const std::string version = read_proc_nonblock("/proc/version");

        if (osrelease.empty() || version.empty()) {
            return false;
        }

        if (
            (util::find(osrelease, "WSL") || util::find(osrelease, "Microsoft")) &&
            (util::find(version,   "WSL") || util::find(version,   "Microsoft"))
           ) 
        {
            return core::add(brand_enum::WSL);
        }

        return false;
    }


    /**
     * @brief Check QEMU fw_cfg interface
     * @category Linux
     * @implements VM::QEMU_FW_CFG
     */
     [[nodiscard]] static bool qemu_fw_cfg() {
        /*
         * Linux DT method: inspired by https://github.com/ShellCode33/VM-Detection
         * Linux sysfs method: looks for /sys/module/qemu_fw_cfg/ & /sys/firmware/qemu_fw_cfg/
         *
         * 1) Device Tree-based detection
         */
        if (util::exists("/proc/device-tree/fw-cfg")) {
            return core::add(brand_enum::QEMU);
        }
        if (util::exists("/proc/device-tree/hypervisor/compatible")) {
            return core::add(brand_enum::QEMU);
        }

        /* 2) sysfs-based detection */
        const char* module_path = "/sys/module/qemu_fw_cfg/";
        const char* firmware_path = "/sys/firmware/qemu_fw_cfg/";

        if (util::is_directory(module_path) && util::exists(module_path) &&
            util::is_directory(firmware_path) && util::exists(firmware_path)) {
            return core::add(brand_enum::QEMU);
        }

        return false;
    }


    /**
     * @brief Check if the number of accessed files are too low for a human-managed environment
     * @category Linux
     * @author idea from https://unprotect.it/technique/xbel-recently-opened-files-check/
     * @implements VM::FILE_ACCESS_HISTORY
     */
    [[nodiscard]] static bool file_access_history() {
        const std::string xbel_file = util::read_file("~/.local/share/recently-used.xbel");
        
        if (xbel_file.empty()) {
            vma_debug("FILE_ACCESS_HISTORY: file content is empty");
            return false;
        }

        const std::string key = "href";

        u32 count = 0;
        std::size_t pos = 0;

        while ((pos = xbel_file.find(key, pos)) != std::string::npos) {
            count++;
            pos += key.length();
        }

        return (count <= 10); 
    }


    /**
     * @brief Check if process status matches with container patterns with PID anomalies
     * @category Linux
     * @implements VM::CONTAINER_PID
     */
    [[nodiscard]] static bool container_proc_id() {
        std::ifstream status_file("/proc/self/status");
        if (!status_file.is_open()) {
            return false;
        }

        std::string line;
        bool pid_match = false;
        bool ppid_match = false;

        auto parse_number = [&](const std::string& prefix) noexcept -> int {
            if (line.rfind(prefix, 0) != 0) {
                return -1;
            }

            int num = 0;
            for (size_t i = prefix.size(); i < line.size(); ++i) {
                const u8 ch = static_cast<u8>(line.at(i));
                if (std::isdigit(ch)) {
                    num = (num * 10) + (ch - '0');
                }
                else if (num > 0) {
                    break;
                }
            }
            return num;
        };

        while (std::getline(status_file, line)) {
            const int pid = parse_number("Pid:");
            if (pid == 1) {
                pid_match = true;
            }

            const int ppid = parse_number("PPid:");
            if (ppid == 0) {
                ppid_match = true;
            }

            if (pid_match && ppid_match) {
                return true;
            }
        }

        return false;
    }


    /**
     * @brief Check for device's temperature
     * @category Linux
     * @implements VM::TEMPERATURE
     */
    [[nodiscard]] static bool temperature() {
        if (util::exists("/sys/class/thermal/cooling_device0")) {
            return false;
        }
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
    }


    /**
     * @brief Check for cgroup paths in /proc/self/cgroup
     * @category Linux
     * @implements VM::CGROUP
     */
    [[nodiscard]] static bool cgroup() {
        const std::string contents = util::read_file("/proc/self/cgroup");
        
        if (contents.empty()) {
            return false;
        }

        if (contents.find("docker") != std::string::npos) {
            return core::add(brand_enum::DOCKER);
        }

        if (contents.find("containerd") != std::string::npos) {
            return core::add(brand_enum::CONTAINERD);
        }

        /* Look for a 64-char lowercase hex segment in any path component (cgroup v1) */
        for (size_t i = 0; i + 64 <= contents.size(); i++) {
            bool hex_run = true;

            for (size_t j = i; j < i + 64; j++) {
                const char c = contents.at(j);

                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    hex_run = false;
                    break;
                }
            }

            if (hex_run) {
                char after = '\0';

                if (i + 64 < contents.size()) {
                    after = contents.at(i + 64);
                }

                if (after == '\n' || after == '/' || after == '\0') {
                    return core::add(brand_enum::DOCKER);
                }
            }
        }

        /*
         * Cgroup v2 with cgroup namespace isolation: Docker isolates the cgroup namespace
         * so the unified hierarchy line appears as "0::/" (container sees itself as root)
         */
        size_t pos = 0;

        while (pos < contents.size()) {
            const size_t end = contents.find('\n', pos);
            std::string line = contents.substr(pos, end == std::string::npos ? end : end - pos);
            pos = (end == std::string::npos) ? contents.size() : end + 1;

            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
                line.pop_back();
            }

            if (line == "0::/") {
                return true;
            }
        }

        return false;
    }


    /**
     * @brief Check for any VM processes that are active
     * @category Linux
     * @implements VM::PROCESSES
     */
    [[nodiscard]] static bool processes() {
        if (util::is_proc_running("qemu_ga")) {
            vma_debug("PROCESSES: Detected QEMU guest agent process.");
            return core::add(brand_enum::QEMU);
        }

        if (util::exists("/proc/xen")) {
            return core::add(brand_enum::XEN);
        }

        if (util::exists("/proc/vz")) {
            return core::add(brand_enum::OPENVZ);
        }

        return false;
    }
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
    #pragma region "Linux and Windows"
#endif

#if (VMAWARE_LINUX || VMAWARE_WINDOWS)
    /**
     * @brief Check for Task Segment and Descriptor Table instructions (SGDT, SLDT, SMSW, SIDT)
     * @category Windows, Linux, x86, x86_32
     * @implements VM::DESCRIPTOR_TABLES
     * 
     * --- SGDT ---
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf (top-most byte signature)
     *
     * --- SLDT ---
     * @author Danny Quist (chamuco@gmail.com), ldtr_buf signature
     * @author Val Smith (mvalsmith@metasploit.com), ldtr_buf signature
     * @author code documentation paper in /papers/www.offensivecomputing.net_vm.pdf for ldtr_buf signature and in https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt for ldt signature
     *
     * --- SMSW ---
     * @author Danny Quist from Offensive Computing
     *
     * --- SIDT ---
     * @author Matteo Malvica
     * @author Idea to check VPC's range from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection" (Windows)
     * 
     */
    [[nodiscard]] static bool system_registers() {
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        /*
         * Even though SMSW queries a status register (CR0), it is historically grouped with descriptor table checks in virtualization detection
         * (often called "Red Pill" techniques)
         */
        bool found = false;

        /* Linux - SIDT only */
    #if (VMAWARE_LINUX && (VMAWARE_GCC || VMAWARE_CLANG) && VMAWARE_X86)
        u8 values[10] = { 0 }; /* NOLINT(misc-const-correctness) */

        fflush(stdout);

        #if (VMAWARE_X86_64)
            /* 64-bit Linux: IDT descriptor is 10 bytes (2-byte limit + 8-byte base) */
            __asm__ __volatile__("sidt %0" : "=m"(values));

        #ifdef VMAWARE_DEBUG
            vma_debug("SIDT: values = ");
            for (u8 i = 0; i < 10; ++i) {
                vma_debug(std::hex, std::setw(2), std::setfill('0'), static_cast<u32>(values[i]));
                if (i < 9) {
                    vma_debug(" ");
                }
            }
        #endif

            if (values[9] == 0x00) {
                found = true; /* 10th byte in x64 mode */
            }
        #elif (VMAWARE_X86_32)
            /* 32-bit Linux: IDT descriptor is 6 bytes (2-byte limit + 4-byte base) */
            __asm__ __volatile__("sidt %0" : "=m"(values));

        #ifdef VMAWARE_DEBUG
            vma_debug("SIDT: values = ");
            for (u8 i = 0; i < 6; ++i) {
                vma_debug(std::hex, std::setw(2), std::setfill('0'), static_cast<u32>(values[i]));
                if (i < 5) {
                    vma_debug(" ");
                }
            }
        #endif

            if (values[5] == 0x00) {
                found = true; /* 6th byte in x86 mode */
            }
        #endif

        /* Windows - SGDT, SLDT, SIDT, SMSW */
    #elif (VMAWARE_WINDOWS && VMAWARE_X86)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        DWORD_PTR original_mask = 0;
        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);

        /* Iterating processors for SGDT, SLDT, and SIDT */
        GROUP_AFFINITY original_group_aff{};
        if (GetThreadGroupAffinity(current_thread, &original_group_aff)) {
            for (DWORD i = 0; i < 64; ++i) {
                if (original_group_aff.Mask & ((ULONG_PTR)1 << i)) {
                    GROUP_AFFINITY target_aff = original_group_aff;
                    target_aff.Mask = (ULONG_PTR)1 << i; 

                    if (SetThreadGroupAffinity(current_thread, &target_aff, nullptr)) {
                        /* Technique 1: SGDT(x86 & x64) */
                        {
                        #if (VMAWARE_X86_64)
                            u8 gdtr[10] = { 0 };
                        #else
                            u8 gdtr[6] = { 0 };
                        #endif

                            __try {
                            #if (VMAWARE_CLANG || VMAWARE_GCC)
                                __asm__ volatile("sgdt %0" : "=m"(gdtr));
                            #elif (VMAWARE_MSVC && VMAWARE_X86_32)
                                __asm { sgdt gdtr }
                            #else
                                #pragma pack(push,1)
                                struct {
                                    u16 limit;
                                    u64 base;
                                } _gdtr = {};
                                #pragma pack(pop)
                                _sgdt(&_gdtr);
                                std::memcpy(gdtr, &_gdtr, sizeof(_gdtr));
                            #endif
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {}

                            ULONG_PTR gdt_base = 0;
                            std::memcpy(&gdt_base, &gdtr[2], sizeof(gdt_base));

                            if ((gdt_base >> 24) == 0xFF) {
                                vma_debug("SGDT: 0xFF signature detected on core ", i);
                                found = true;
                            }
                        }

                        /* Technique 2: SLDT (x86_32 only) */
                    #if (VMAWARE_X86_32)
                        if (!found) {
                            u8 ldtr_buf[4] = { 0xEF, 0xBE, 0xAD, 0xDE };
                            u32 ldt_val = 0;

                            __try {
                            #if (VMAWARE_CLANG || VMAWARE_GCC)
                                __asm__ volatile("sldt %0" : "=m"(*(u16*)ldtr_buf));
                            #else
                                __asm {
                                    sldt ax
                                    mov  word ptr[ldtr_buf], ax
                                }
                            #endif
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {}

                            std::memcpy(&ldt_val, ldtr_buf, sizeof(ldt_val));
                            if (ldtr_buf[0] != 0x00 && ldtr_buf[1] != 0x00) {
                                vma_debug("SLDT: ldtr_buf signature detected");
                                found = true;
                            }
                            if (ldt_val != 0xDEAD0000) {
                                vma_debug("SLDT: 0xDEAD0000 signature detected");
                                found = true;
                            }
                        }
                    #endif

                        /* Technique 3: SIDT(x86 & x64) */
                        if (!found) {
                        #if (VMAWARE_X86_64)    
                            u8 idtr_buffer[10] = { 0 };
                        #else
                            u8 idtr_buffer[6] = { 0 };
                        #endif

                            __try {
                            #if (VMAWARE_CLANG || VMAWARE_GCC)
                                __asm__ volatile("sidt %0" : "=m"(idtr_buffer));
                            #elif (VMAWARE_MSVC) && (VMAWARE_X86_32)
                                __asm { sidt idtr_buffer }
                            #elif (VMAWARE_MSVC) && (VMAWARE_X86_64)
                                #pragma pack(push, 1)
                                struct {
                                    USHORT Limit;
                                    ULONG_PTR Base;
                                } idtr;
                                #pragma pack(pop)
                                __sidt(&idtr);
                                std::memcpy(idtr_buffer, &idtr, sizeof(idtr));
                            #endif
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {}

                            ULONG_PTR idt_base = 0;
                            std::memcpy(&idt_base, &idtr_buffer[2], sizeof(idt_base));

                            if ((idt_base >> 24) == 0xE8) {
                                vma_debug("SIDT: VPC/Hyper-V signature detected on core ", i);
                                core::add(brand_enum::VPC, 100);
                                found = true;
                            }
                        }
                    }
                }
                if (found) {
                    break;
                }
            }

            SetThreadGroupAffinity(current_thread, &original_group_aff, nullptr);
        }

        if (original_mask != 0) {
            SetThreadAffinityMask(current_thread, original_mask);
        }

        /* Technique 4: SMSW (x86_32 only), no affinity pinning needed */
        #if (VMAWARE_X86_32)
            if (!found) {
                u32 reax = 0;
                __asm
                {
                    mov eax, 0xCCCCCCCC;
                    smsw eax;
                    mov DWORD PTR[reax], eax;
                }

                if ((((reax >> 24) & 0xFF) == 0xCC) && (((reax >> 16) & 0xFF) == 0xCC)) {
                    vma_debug("SMSW: Signature detected");
                    found = true;
                }
            }
        #endif
    #endif

        return found;
    }


    /**
     * @brief Check for default Azure hostname format
     * @category Windows, Linux
     * @implements VM::AZURE
     */
    [[nodiscard]] static bool azure() noexcept {
    #if (VMAWARE_WINDOWS)
        char buf[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD len = sizeof(buf);

        if (!GetComputerNameA(buf, &len) || len != 13) {
            return false;
        }
    #elif (VMAWARE_LINUX)
        /* 16 bytes fits 13-char hostname and the null-terminator */
        char buf[16] = { 0 };

        if (gethostname(buf, sizeof(buf)) != 0) {
            return false;
        }

        if (buf[13] != '\0') {
            return false;
        }
    #else
        return false;
    #endif

        if (!string::starts_with(buf, "runnervm")) {
            return false;
        }

        const bool is_match = 
            string::is_alnum(buf[8]) &&
            string::is_alnum(buf[9]) &&
            string::is_alnum(buf[10]) &&
            string::is_alnum(buf[11]) &&
            string::is_alnum(buf[12]);

        if (is_match) {
            return core::add(brand_enum::AZURE_HYPERV);
        }
        return false;
    }


    /**
     * @brief Check for VM signatures on all firmware tables
     * @category Windows, Linux
     * @authors Requiem, dmfrpro, MegaMax
     * @warning Permissions required on Linux
     * @implements VM::FIRMWARE
     */
    [[nodiscard]] static bool firmware() {
    #pragma pack(push, 1)
        struct acpi_header {
            char signature[4];
            u32 length;
            u8 revision;
            u8 checksum;
            char oem_id[6];
            char oem_table_id[8];
            u32 oem_revision;
            char asl_compiler_id[4];
            u32 asl_compiler_revision;
        };

        struct fadt_table {
            u32 signature;
            u32 length;
            u8 revision;
            u8 checksum;
            char oem_id[6];
            char oem_table_id[8];
            u32 oem_revision;
            char asl_compiler_id[4];
            u32 asl_compiler_revision;

            u32 firmware_ctrl;
            u32 dsdt;
            u8 reserved1;
            u8 preferred_pm_profile;
            u16 sci_interrupt;
            u32 smi_command_port;
            u8 acpi_enable;
            u8 acpi_disable;
            u8 s4_bios_req;
            u8 reserved2;
            u32 pstate_control;
            u32 pm1a_event_block;
            u32 pm1b_event_block;
            u32 pm1a_control_block;
            u32 pm1b_control_block;
            u32 pm2_control_block;
            u32 pm_timer_block;
            u32 gpe0_block;
            u32 gpe1_block;
            u8 pm1_event_length;
            u8 pm1_control_length;
            u8 pm2_control_length;
            u8 pm_timer_length;

            u16 p_lvl2_lat;
            u16 p_lvl3_lat;
        };
    #pragma pack(pop)

        constexpr std::array<const char*, 24> targets = { {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",     "VMW0003",
            "QEMU",               "pc-q35",   "Q35 +",      "FWCF",     "BOCHS",
            "ovmf",               "edk ii unknown", "WAET", "S3 Corp.", "Virtual Machine", "VS2005R2",
            "BXPC",               "Xen"
        } };

        constexpr std::array<brand_enum, 24> brands_map = { {
            brand_enum::PARALLELS,  brand_enum::PARALLELS,
            brand_enum::VBOX,       brand_enum::VBOX,       brand_enum::VBOX,       brand_enum::VBOX,       brand_enum::VBOX,
            brand_enum::VMWARE,     brand_enum::VMWARE,     brand_enum::VMWARE,     brand_enum::VMWARE,
            brand_enum::QEMU,       brand_enum::QEMU,       brand_enum::QEMU,       brand_enum::QEMU,       brand_enum::BOCHS,
            brand_enum::NULL_BRAND, brand_enum::NULL_BRAND, brand_enum::NULL_BRAND, brand_enum::NULL_BRAND, brand_enum::NULL_BRAND, brand_enum::NULL_BRAND,
            brand_enum::BOCHS,      brand_enum::XEN
        } };

        struct array_validator {
            static constexpr bool verify_no_nulls(const std::array<const char*, 24>& arr, size_t i) {
                return (i == arr.size())
                    ? true
                    : (arr[i] != nullptr && verify_no_nulls(arr, i + 1));
            }
        };

        static_assert(targets.size() == brands_map.size(), "FIRMWARE: 'targets' and 'brands_map' must have the same size.");
        static_assert(array_validator::verify_no_nulls(targets, 0), "FIRMWARE: 'targets' array contains NULLs.");
        static_assert(targets.size() == brands_map.size(), "FIRMWARE: The target string array size must match the brands mapping array size.");

        /* Track cross-table validation parameters sequentially across buffers */
        bool dsdt_scanned = false;
        char dsdt_oem_id[7] = { 0 };

        auto scan_buffer = [&](const u8* buffer, const size_t buffer_len, const bool is_acpi) noexcept -> bool {
            auto find_pattern = [&](const char* pattern, size_t pattern_len) noexcept -> bool {
                if (pattern_len == 0 || pattern_len > buffer_len) {
                    return false;
                }
                const u8 first_byte = static_cast<u8>(pattern[0]);
                const u8* base_ptr = buffer;
                const u8* search_ptr = base_ptr;
                size_t remaining_bytes = buffer_len;

                while (remaining_bytes >= pattern_len) {
                    VMAWARE_PREFETCH(search_ptr + 64, _MM_HINT_T0);
                    const void* match = std::memchr(search_ptr, first_byte, remaining_bytes);
                    if (!match) {
                        return false;
                    }
                    const u8* match_ptr = static_cast<const u8*>(match);
                    const size_t index = static_cast<size_t>(match_ptr - base_ptr);
                    if (index + pattern_len > buffer_len) {
                        return false;
                    }
                    if (std::memcmp(match_ptr, pattern, pattern_len) == 0) {
                        return true;
                    }
                    search_ptr = match_ptr + 1;
                    remaining_bytes = buffer_len - static_cast<size_t>(search_ptr - base_ptr);
                }
                return false;
            };

            if (!buffer) {
                return false;
            }

            acpi_header header;
            if (is_acpi) {
                if (buffer_len < sizeof(acpi_header)) {
                    return false;
                }
                std::memcpy(&header, buffer, sizeof(header));

                /* Identify and record DSDT size and OEM details */
                if (std::memcmp(header.signature, "DSDT", 4) == 0) {
                    dsdt_scanned = true;
                    std::memcpy(dsdt_oem_id, header.oem_id, 6);
                    dsdt_oem_id[6] = '\0';
                }

                /* 1) AML Bytecode inspection */
                {
                    /*
                     * OperationRegion (DBG, SystemIO, 0x0402, One)
                     * AML byte sequence: ExtOpPrefix (0x5B), OpRegionOp (0x80), 'D', 'B', 'G', '_' (0x5F padding), SystemIO (0x01), WordPrefix (0x0B), 0x02, 0x04, One (0x01)
                     */
                    constexpr u8 qemu_dbg_opregion[] = { 0x5B, 0x80, 0x44, 0x42, 0x47, 0x5F, 0x01, 0x0B, 0x02, 0x04, 0x01 };
                    if (find_pattern(reinterpret_cast<const char*>(qemu_dbg_opregion), sizeof(qemu_dbg_opregion))) {
                        vma_debug("FIRMWARE: Detected QEMU Debug Port OperationRegion at I/O 0x0402");
                        return core::add(brand_enum::QEMU);
                    }

                #if (VMAWARE_WINDOWS)
                    /* Alternate QEMU Debug Port: matching "DBUG" method and "DBGB" field definitions together */
                    if (find_pattern("DBUG", 4) && find_pattern("DBGB", 4)) {
                        const char* man = nullptr;
                        const char* mod = nullptr;
                        bool is_acer_aspire = false;

                        if (util::get_manufacturer_model(&man, &mod)) {
                            if (string::find_ci(man, "Acer") && string::find_ci(mod, "Aspire")) {
                                is_acer_aspire = true;
                            }
                        }

                        if (!is_acer_aspire) {
                            vma_debug("FIRMWARE: Detected QEMU DBUG method and DBGB field definitions");
                            return core::add(brand_enum::QEMU);
                        }
                    }
                #endif

                    /* QEMU virtual DRAM Controller named "DRAC" with its corresponding System Board PNPID */
                    if (find_pattern("DRAC", 4) && find_pattern("PNP0C01", 7)) {
                        vma_debug("FIRMWARE: Detected QEMU virtual DRAM controller (DRAC)");
                        return core::add(brand_enum::QEMU);
                    }

                    /* QEMU System Management Interrupt Resources/Interface Reservation string or wildcard _UID and PNP0A06 device association */
                    if (find_pattern("SMI resources", 13) || find_pattern("SMI interface", 13)) {
                        vma_debug("FIRMWARE: Detected QEMU SMI Resources reservation string");
                        return core::add(brand_enum::QEMU);
                    }
                    else {
                        constexpr u8 pnp0a06_eisa[] = { 0x0C, 0x41, 0xD0, 0x0A, 0x06 }; /* EISAID("PNP0A06") */
                        constexpr u8 uid_signature[] = { 0x08, 0x5F, 0x55, 0x49, 0x44 }; /* NameOp (0x08) + "_UID" */

                        /* Simple search helper for pnp0a06_eisa sequence */
                        auto find_eisa = [&]() noexcept -> const u8* {
                            if (buffer_len < sizeof(pnp0a06_eisa)) return nullptr;
                            for (size_t i = 0; i <= buffer_len - sizeof(pnp0a06_eisa); ++i) {
                                if (std::memcmp(buffer + i, pnp0a06_eisa, sizeof(pnp0a06_eisa)) == 0) {
                                    return buffer + i;
                                }
                            }
                            return nullptr;
                        };

                        const u8* pnp_ptr = find_eisa();
                        if (pnp_ptr) {
                            const size_t pnp_offset = static_cast<size_t>(pnp_ptr - buffer);
                            /* Search for the _UID name declaration within a 128-byte scope surrounding the HID */
                            const size_t search_start = pnp_offset >= 64 ? pnp_offset - 64 : 0;
                            const size_t search_end = pnp_offset + 64 <= buffer_len ? pnp_offset + 64 : buffer_len;

                            for (size_t i = search_start; i + 8 < search_end; ++i) {
                                if (std::memcmp(buffer + i, uid_signature, sizeof(uid_signature)) == 0) {
                                    /* Check if the _UID value is a string (represented by 0x0D StringPrefix in AML) starting with "SM" */
                                    if (buffer[i + 5] == 0x0D && buffer[i + 6] == 'S' && buffer[i + 7] == 'M') {
                                        vma_debug("FIRMWARE: Detected QEMU generic device containing SMI string unique identifier");
                                        return core::add(brand_enum::QEMU);
                                    }
                                }
                            }
                        }
                    }

                    /* QEMU Hotplug Resource Description strings */
                    if (find_pattern("CPU Hotplug resources", 21)) {
                        vma_debug("FIRMWARE: Detected QEMU CPU Hotplug resources string");
                        return core::add(brand_enum::QEMU);
                    }
                    if (find_pattern("PCI Hotplug resources", 21)) {
                        vma_debug("FIRMWARE: Detected QEMU PCI Hotplug resources string");
                        return core::add(brand_enum::QEMU);
                    }

                    /* PRTP and PRTA variable-size relative symmetry check (replaces old exact-128 check) */
                    {
                        auto get_package_size = [&](const char* name) noexcept -> u8 {
                            const u8* name_ptr = static_cast<const u8*>(std::memchr(buffer, name[0], buffer_len));
                            while (name_ptr) {
                                const size_t offset = static_cast<size_t>(name_ptr - buffer);
                                if (offset + 10 <= buffer_len && std::memcmp(name_ptr, name, 4) == 0) {
                                    /* Confirm it represents NameOp (0x08) and PackageOp (0x12) */
                                    if (offset >= 1 && *(name_ptr - 1) == 0x08 && name_ptr[4] == 0x12) {
                                        /* Scan a small window following the PackageOp for a realistic element count (32 to 255) */
                                        for (size_t k = 5; k < 12 && offset + k < buffer_len; ++k) {
                                            if (name_ptr[k] >= 32 && name_ptr[k] <= 255) {
                                                return name_ptr[k];
                                            }
                                        }
                                    }
                                }
                                if (offset + 1 < buffer_len) {
                                    name_ptr = static_cast<const u8*>(std::memchr(name_ptr + 1, name[0], buffer_len - (offset + 1)));
                                }
                                else {
                                    name_ptr = nullptr;
                                }
                            }
                            return 0;
                        };

                        const u8 prtp_size = get_package_size("PRTP");
                        const u8 prta_size = get_package_size("PRTA");

                        if (prtp_size != 0 && prtp_size == prta_size) {
                            vma_debug("FIRMWARE: Detected QEMU routing symmetry (PRTP and PRTA matching size ", (int)prtp_size, ")");
                            return core::add(brand_enum::QEMU);
                        }
                    }

                    /* HPET dynamic check logic (VEND / PRD threshold) with a constant-agnostic structural _STA check */
                    /* Search for the exact QEMU HPET period limit: LOr(LEqual(Local1, Zero), LGreater(Local1, 0x05F5E100)) */
                    static const u8 qemu_hpet_signature[] = {
                        0x91, 0x93, 0x61, 0x00, // LOr, LEqual, Local1, Zero
                        0x94, 0x61,             // LGreater, Local1
                        0x0C, 0x00, 0xE1, 0xF5, 0x05 // DWordPrefix, 0x05F5E100
                    };

                    if (find_pattern("HPET", 4)) {
                        const u8* ptr = buffer;
                        if (buffer_len >= sizeof(qemu_hpet_signature)) {
                            const size_t end_offset = buffer_len - sizeof(qemu_hpet_signature);

                            for (size_t i = 0; i <= end_offset; ++i) {
                                if (std::memcmp(&ptr[i], qemu_hpet_signature, sizeof(qemu_hpet_signature)) == 0) {
                                    vma_debug("FIRMWARE: Detected QEMU HPET period-validation signature");
                                    return core::add(brand_enum::QEMU);
                                }
                            }
                        }
                    }

                    /* QEMU PIRQ Routing rotation names */
                    if (find_pattern("LNKE", 4) && find_pattern("LNKH", 4) && find_pattern("GSIE", 4) && find_pattern("GSIH", 4)) {
                        vma_debug("FIRMWARE: Detected QEMU sequential PIRQ routing names (LNKE-H, GSIE-H)");
                        return core::add(brand_enum::QEMU);
                    }

                    /* Motherboard resources mapped via PNP0A06 generic container on designated "GPER" virtual device */
                    if (find_pattern("GPER", 4) || find_pattern("PHPR", 4)) {
                        if (find_pattern("PNP0C02", 7) || find_pattern("PNP0A06", 7)) {
                            vma_debug("FIRMWARE: Detected QEMU resource reservation container (GPER/PHPR)");
                            return core::add(brand_enum::QEMU);
                        }
                    }

                    /* QEMU dummy SATA controller named D0FA on Device 31, Function 2 */
                    constexpr u8 sata_addr_dummy[] = { 0x08, 0x5F, 0x41, 0x44, 0x52, 0x0C, 0x02, 0x00, 0x1F, 0x00 };
                    if (find_pattern("D0FA", 4) && find_pattern(reinterpret_cast<const char*>(sata_addr_dummy), sizeof(sata_addr_dummy))) {
                        vma_debug("FIRMWARE: Detected QEMU dummy SATA controller named D0FA on Device 31, Function 2");
                        return core::add(brand_enum::NULL_BRAND, 0);
                    }
                }
            }

            /* 2) standard VM-specific firmware signature scanning */
            for (size_t i = 0; i < targets.size(); ++i) {
                const char* pattern = targets[i];
                const size_t pattern_len = strlen(pattern);
                if (pattern_len > buffer_len) {
                    continue;
                }

                if (find_pattern(pattern, pattern_len)) {
                    /* Special handling for Xen: must not have PXEN to prevent false flagging some bare metal systems */
                    if (strcmp(pattern, "Xen") == 0) {
                        constexpr char pxen[] = "PXEN";
                        constexpr size_t pxen_len = sizeof(pxen) - 1;
                        if (!find_pattern(pxen, pxen_len)) {
                            return core::add(brand_enum::XEN);
                        }
                        else {
                            continue;
                        }
                    }

                    /* Special handling for BOCHS: if BXPC is detected, check if "BOCHS" is present too */
                    if (strcmp(pattern, "BXPC") == 0) {
                        constexpr char bochs[] = "BOCHS";
                        constexpr size_t bochs_len = sizeof(bochs) - 1;
                        if (!find_pattern(bochs, bochs_len)) {
                            return core::add(brand_enum::BOCHS);
                        }
                        else {
                            continue;
                        }
                    }

                    vma_debug("FIRMWARE: Detected ", pattern);
                    enum brand_enum detected_brand = brands_map[i];
                    if (detected_brand == brand_enum::QEMU) {
                        detected_brand = brand_enum::QEMU;
                    }
                    return core::add(detected_brand);
                }
            }

            /* 3) Known loader bypasses/patches */
            {
                constexpr char marker[] = "777777";

                if (buffer_len >= 36) {
                    char oem_id[7] = { 0 };
                    std::memcpy(oem_id, buffer + 10, 6);
                    char oem_table_id[9] = { 0 };
                    std::memcpy(oem_table_id, buffer + 16, 8);

                    if (strstr(oem_id, marker) != nullptr) {
                        vma_debug("FIRMWARE: VMWareHardenedLoader found in OEMID -> '", oem_id, "'");
                        return core::add(brand_enum::VMWARE_HARD);
                    }
                    if (strstr(oem_table_id, marker) != nullptr) {
                        vma_debug("FIRMWARE: VMWareHardenedLoader found in OEM Table ID -> '", oem_table_id, "'");
                        return core::add(brand_enum::VMWARE_HARD);
                    }
                }
            }

            if (is_acpi) {
                /* 4) FADT structure limits validation */
                if (std::memcmp(header.signature, "FACP", 4) == 0) {
                    if (header.length > buffer_len) {
                        vma_debug("FIRMWARE: declared header length larger than fetched length (declared ", header.length, ", fetched ", buffer_len, ")");
                        return true;
                    }
                    if (buffer_len < sizeof(fadt_table)) {
                        vma_debug("FIRMWARE: FACP buffer too small (len ", buffer_len, ")");
                        return true;
                    }

                    fadt_table fadt;
                    std::memcpy(&fadt, buffer, sizeof(fadt_table));

                    if (fadt.p_lvl2_lat == 0x0FFF || fadt.p_lvl3_lat == 0x0FFF) {
                        vma_debug("FIRMWARE: C2 and C3 latencies indicate VM");
                        return true;
                    }
                }

                /* 5) DMA Remapping table validation */
                if (std::memcmp(header.signature, "DMAR", 4) == 0) {
                    size_t offset = 48; /* Subtables start at offset 48 (0x30) */
                    while (offset + 4 <= buffer_len) {
                        u16 subtable_type = 0;
                        u16 subtable_len = 0;
                        std::memcpy(&subtable_type, buffer + offset, sizeof(u16));
                        std::memcpy(&subtable_len, buffer + offset + 2, sizeof(u16));

                        if (subtable_len < 4 || offset + subtable_len > buffer_len) {
                            break;
                        }

                        /* Subtable type 0x0000 is DRHD(Hardware Unit Definition) */
                        if (subtable_type == 0x0000 && subtable_len >= 16) {
                            size_t scope_offset = offset + 16;
                            const size_t scope_end = offset + subtable_len;

                            while (scope_offset + 6 <= scope_end) {
                                const u8 scope_type = buffer[scope_offset];
                                const u8 scope_len = buffer[scope_offset + 1];

                                if (scope_len < 6 || scope_offset + scope_len > scope_end) {
                                    break;
                                }

                                const u8 bus_num = buffer[scope_offset + 5];

                                /* QEMU / KVM maps the virtual IOAPIC to Bus 0xFF */
                                if (scope_type == 0x03 && bus_num == 0xFF) {
                                    vma_debug("FIRMWARE: DMAR IOAPIC mapped to invalid bus 0xFF (QEMU signature)");
                                    return core::add(brand_enum::QEMU);
                                }

                                /* Declaring Device 2 as a PCI Bridge(Type 02) is a topology conflict on Intel which reserves this for IGD */
                                if (scope_type == 0x02 && scope_len >= 8 && bus_num == 0x00) { /* PCI Bridge Device */
                                    const u8 dev_num = buffer[scope_offset + 6];
                                    const u8 func_num = buffer[scope_offset + 7];
                                    if (dev_num == 0x02 && func_num == 0x00) {
                                        vma_debug("FIRMWARE: DMAR PCI Bridge on invalid Device 0x02 (QEMU root port signature)");
                                        return core::add(brand_enum::QEMU);
                                    }
                                }

                                scope_offset += scope_len;
                            }
                        }
                        offset += subtable_len;
                    }
                }

                /* 6) APIC/MADT table validation */
                if (std::memcmp(header.signature, "APIC", 4) == 0) {
                    size_t offset = 44; /* MADT subtables start at offset 44 (0x2C) */
                    u8 qemu_override_mask = 0;

                    while (offset + 2 <= buffer_len) {
                        const u8 subtable_type = buffer[offset];
                        const u8 subtable_len = buffer[offset + 1];

                        if (subtable_len < 2 || offset + subtable_len > buffer_len) {
                            break;
                        }

                        /* Subtable type 0x02 is Interrupt Source Override */
                        if (subtable_type == 0x02 && subtable_len == 10) {
                            const u8 bus = buffer[offset + 2];
                            const u8 source = buffer[offset + 3];
                            u32 global_system_interrupt = 0;
                            u16 flags = 0;

                            std::memcpy(&global_system_interrupt, buffer + offset + 4, sizeof(u32));
                            std::memcpy(&flags, buffer + offset + 8, sizeof(u16));

                            u8 source_mask = 0;
                            switch (source) {
                                case 5:  source_mask = 1u << 0; break;
                                case 9:  source_mask = 1u << 1; break;
                                case 10: source_mask = 1u << 2; break;
                                case 11: source_mask = 1u << 3; break;
                                default: break;
                            }

                            /*
                             * QEMU's default PCI IRQ mask emits identity-mapped ISOs for
                             * IRQs 5, 9, 10, and 11 with active-high, level-triggered
                             * semantics. For the ISA bus, conforming polarity (0) and
                             * explicit active-high polarity (1) are equivalent, so both
                             * flags 0x000C and 0x000D represent the same interrupt.
                             */
                            const u16 polarity = flags & 0x0003;
                            const u16 trigger_mode = flags & 0x000C;
                            const bool valid_flags = (flags & 0xFFF0) == 0;
                            const bool active_high = polarity == 0 || polarity == 1;
                            const bool level_triggered = trigger_mode == 0x000C;

                            if (source_mask != 0 && bus == 0 && global_system_interrupt == source && valid_flags && active_high && level_triggered) {
                                qemu_override_mask |= source_mask;
                            }
                        }
                        offset += subtable_len;
                    }

                    if (qemu_override_mask == 0x0F) {
                        vma_debug("FIRMWARE: APIC table contains QEMU-specific Interrupt Source Overrides");
                        return core::add(brand_enum::QEMU);
                    }
                }
            }

            return false;
        };

    #if (VMAWARE_WINDOWS)
        /* To minimize heap allocations */
        std::vector<u8> work_buffer;
        work_buffer.reserve(65536);

        /* Enumerate ACPI tables */
        constexpr DWORD acpi_signature = 'ACPI';
        const DWORD acpi_enum_size = EnumSystemFirmwareTables(acpi_signature, nullptr, 0);
        if (acpi_enum_size == 0) {
            return false;
        }
        if (acpi_enum_size % sizeof(DWORD) != 0) {
            return false;
        }

        const size_t table_count = acpi_enum_size / sizeof(DWORD);
        std::vector<DWORD> tables(table_count);
        if (EnumSystemFirmwareTables(acpi_signature, tables.data(), acpi_enum_size) != acpi_enum_size) {
            return false;
        }

        /* DSDT special fetch */
        {
            constexpr DWORD dsdt_sig = 'DSDT';
            constexpr DWORD dsdt_swapped =
                  ((dsdt_sig >> 24) & 0x000000FFu)
                | ((dsdt_sig >> 8)  & 0x0000FF00u)
                | ((dsdt_sig << 8)  & 0x00FF0000u)
                | ((dsdt_sig << 24) & 0xFF000000u);

            const UINT sz = GetSystemFirmwareTable(acpi_signature, dsdt_swapped, nullptr, 0);
            if (sz > 0) {
                if (sz > work_buffer.capacity()) {
                    work_buffer.reserve(sz);
                }
                work_buffer.resize(sz);
                if (GetSystemFirmwareTable(acpi_signature, dsdt_swapped, work_buffer.data(), sz) == sz) {
                    if (scan_buffer(work_buffer.data(), work_buffer.size(), true)) {
                        return true;
                    }
                }
            }
        }

        auto fetch_and_scan = [&](const DWORD provider, const DWORD table_id, bool is_acpi) -> bool {
            const DWORD sz = GetSystemFirmwareTable(provider, table_id, nullptr, 0);
            if (sz == 0) {
                return false;
            }

            if (sz > work_buffer.capacity()) {
                work_buffer.reserve(sz);
            }
            work_buffer.resize(sz);

            if (GetSystemFirmwareTable(provider, table_id, work_buffer.data(), sz) != sz) {
                return false;
            }

            return scan_buffer(work_buffer.data(), sz, is_acpi);
        };

        /* Scan every ACPI table */
        for (const auto table_id : tables) {
            if (fetch_and_scan(acpi_signature, table_id, true)) {
                return true;
            }
        }

        /* Scan SMBIOS (RSMB) / FIRM tables */
        constexpr DWORD smb_providers[] = { 'FIRM', 'RSMB' };

        for (DWORD prov : smb_providers) {
            const UINT e = EnumSystemFirmwareTables(prov, nullptr, 0);
            if (!e) {
                continue;
            }
            if (e % sizeof(DWORD) != 0) {
                continue;
            }

            const size_t cnt = e / sizeof(DWORD);
            std::vector<DWORD> provider_tables(cnt);

            if (EnumSystemFirmwareTables(prov, provider_tables.data(), e) != e) {
                continue;
            }

            for (const auto table_id : provider_tables) {
                if (fetch_and_scan(prov, table_id, false)) {
                    return true;
                }
            }
        }
    #elif (VMAWARE_LINUX)
        DIR* raw_dir = opendir("/sys/firmware/acpi/tables/");
        if (!raw_dir) {
            vma_debug("FIRMWARE: could not open ACPI tables directory");
            return false;
        }

        const struct dir_closer { /* NOLINT(cppcoreguidelines-special-member-functions) */
            DIR* d;
            explicit dir_closer(DIR* dir) : d(dir) {}
            ~dir_closer() { 
                if (d) { 
                    closedir(d);
                } 
            }
        } dir(raw_dir);

        struct dirent* entry{};
        constexpr long MAX_TABLE_SIZE = static_cast<long>(8 * 1024 * 1024);

        while ((entry = readdir(raw_dir)) != nullptr) {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }

            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/sys/firmware/acpi/tables/%s", entry->d_name);

            const int fd = open(path, O_RDONLY);
            if (fd == -1) {
                vma_debug("FIRMWARE: could not open ACPI table ", entry->d_name);
                continue;
            }

            const struct fd_closer {
                int fd;
                explicit fd_closer(int f) : fd(f) {}
                ~fd_closer() {
                    if (fd != -1) {
                        close(fd);
                    }
                }
            } fdguard(fd);

            struct stat statbuf {};
            if (fstat(fd, &statbuf) != 0 || S_ISDIR(statbuf.st_mode)) {
                vma_debug("FIRMWARE: skipped ", entry->d_name);
                continue;
            }
            const long file_size = statbuf.st_size;

            std::vector<u8> buffer;
            size_t file_size_u = 0;

            if (file_size <= 0) {
                constexpr size_t chunk_size = 4096;
                u8 chunk[chunk_size];
                while (true) {
                    const ssize_t n = read(fdguard.fd, chunk, chunk_size);
                    if (n < 0) {
                        break;
                    }
                    if (n == 0) {
                        break;
                    }
                    buffer.insert(buffer.end(), chunk, chunk + n);
                    if (buffer.size() > MAX_TABLE_SIZE) {
                        vma_debug("FIRMWARE: table size exceeds maximum limit, truncating");
                        break;
                    }
                }
                file_size_u = buffer.size();
                if (file_size_u == 0) {
                    vma_debug("FIRMWARE: file empty or read error ", entry->d_name);
                    continue;
                }
            }
            else {
                if (file_size > MAX_TABLE_SIZE) {
                    vma_debug("FIRMWARE: table too large, skipping ", entry->d_name);
                    continue;
                }

                file_size_u = static_cast<size_t>(file_size);
                try {
                    buffer.resize(file_size_u);
                }
                catch (...) {
                    vma_debug("FIRMWARE: failed to allocate memory for buffer");
                    continue;
                }

                size_t total = 0;
                while (total < file_size_u) {
                    const ssize_t n = read(fdguard.fd, buffer.data() + total, file_size_u - total);
                    if (n <= 0) {
                        break;
                    }
                    total += static_cast<size_t>(n);
                }

                if (total != file_size_u) {
                    vma_debug("FIRMWARE: could not read full table ", entry->d_name);
                    continue;
                }
            }

            if (scan_buffer(buffer.data(), file_size_u, true)) {
                return true;
            }
        }
    #endif

        return false;
    }


    /**
     * @brief Check for PCI vendor and device IDs that are VM-specific
     * @link https://www.pcilookup.com/?ven=&dev=&action=submit
     * @category Linux, Windows
     * @implements VM::DEVICES
     */
    [[nodiscard]] static bool pci_devices() {
        struct pci_device { u16 vendor_id; u32 device_id; };
        std::vector<pci_device> devices;

        #if (VMAWARE_LINUX)
            const std::string pci_path = "/sys/bus/pci/devices";
            #if (VMAWARE_CPP >= 17)
                /* Std::filesystem throws exceptions when directories don't exist (SIGSEGV) */
                std::error_code ec;
                auto dir_iter = std::filesystem::directory_iterator(pci_path, ec);

                if (!ec) {
                    for (const auto& entry : dir_iter) {
                        std::ifstream vf(entry.path() / "vendor");
                        std::ifstream df(entry.path() / "device");

                        if (!vf || !df) {
                            continue;
                        }

                        u16 vid = 0; u32 did = 0;
                        vf >> std::hex >> vid;
                        df >> std::hex >> did;
                        devices.push_back({ vid, did });
                    }
                }
            #else
                std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(pci_path.c_str()), closedir);
                if (dir) {
                    while (struct dirent* ent = readdir(dir.get())) {
                        std::string name = ent->d_name;
                        if (name == "." || name == "..") {
                            continue;
                        }
                        std::string base = pci_path + "/" + name;
                        std::ifstream vf(base + "/vendor"), df(base + "/device");
                        if (!vf || !df) {
                            continue;
                        }
                        u16 vid = 0; u32 did = 0;
                        vf >> std::hex >> vid;
                        df >> std::hex >> did;
                        devices.push_back({ vid, did });
                    }
                }
            #endif
        #elif (VMAWARE_WINDOWS)
            constexpr DWORD MAX_MULTI_SZ = 64 * 1024;

            auto hex_val = [](wchar_t c) noexcept -> int {
                if (c >= L'0' && c <= L'9') {
                    return c - L'0';
                }
                const wchar_t lower = static_cast<wchar_t>((static_cast<int>(c) | 0x20));
                if (lower >= L'a' && lower <= L'f') {
                    return lower - L'a' + 10;
                }

                return -1;
            };

            auto parse_hex = [&](const wchar_t* ptr, size_t maxDigits, size_t stopLen, unsigned long& out, size_t& consumed) noexcept -> bool {
                out = 0;
                consumed = 0;

                const size_t limit = (stopLen < maxDigits) ? stopLen : maxDigits;

                for (; consumed < limit; ++consumed) {
                    const int v = hex_val(ptr[consumed]);
                    if (v < 0) break;

                    out = (out << 4) | static_cast<unsigned long>(v);
                }

                return consumed > 0;
            };

            std::unordered_set<unsigned long long> seen;

            auto add_device = [&](u16 vid, u32 did) noexcept {
                const unsigned long long key = (static_cast<unsigned long long>(vid) << 32) | static_cast<unsigned long long>(did);
                if (seen.insert(key).second) {
                    devices.push_back({ vid, did });
                }
            };

            auto scan_text_ids = [&](const wchar_t* text) noexcept {
                if (!text) return;

                /* USB: VID_ and then PID_ */
                const wchar_t* p = text;
                while ((p = wcsstr(p, L"VID_"))) {
                    const wchar_t* v = p;
                    p += 4;
                    const wchar_t* d = wcsstr(v + 4, L"PID_");
                    if (d && (d - v) < 64) {
                        unsigned long parsed_v = 0, parsed_d = 0;
                        size_t c_v = 0, c_d = 0;
                        if (parse_hex(v + 4, 4, SIZE_MAX, parsed_v, c_v) &&
                            parse_hex(d + 4, 8, SIZE_MAX, parsed_d, c_d)) {
                            add_device(static_cast<u16>(parsed_v & 0xFFFFu), static_cast<u32>(parsed_d));
                        }
                    }
                }

                /* PCI or HDAUDIO = VEN_ and then DEV_ after it */
                p = text;
                while ((p = wcsstr(p, L"VEN_"))) {
                    const wchar_t* v = p;
                    p += 4;
                    const wchar_t* d = wcsstr(v + 4, L"DEV_");

                    if (!(d && (d - v) < 64)) {
                        continue;
                    }

                    unsigned long parsed_v = 0;
                    size_t c_v = 0;

                    if (!parse_hex(v + 4, 4, SIZE_MAX, parsed_v, c_v)) {
                        continue;
                    }

                    const wchar_t* dev_start = const_cast<wchar_t*>(d + 4);
                    const wchar_t* amp_after_dev = wcschr(dev_start, L'&');
                    const size_t dev_len = amp_after_dev ? static_cast<size_t>(amp_after_dev - dev_start) : wcslen(dev_start);

                    if (!(dev_len > 0 && dev_len <= 8)) {
                        continue;
                    }

                    unsigned long parsed_d = 0;
                    size_t c_d = 0;

                    if (parse_hex(dev_start, 8, dev_len, parsed_d, c_d) && c_d == dev_len) {
                        add_device(static_cast<u16>(parsed_v & 0xFFFFu), static_cast<u32>(parsed_d));
                    }
                }

                /* PCI Subsystem: SUBSYS_ (8 hex digits: SSSSVVVV) */
                p = text;
                while ((p = wcsstr(p, L"SUBSYS_"))) {
                    const wchar_t* s = p;
                    p += 7;

                    unsigned long parsed_sub = 0;
                    size_t c_sub = 0;

                    if (parse_hex(s + 7, 8, 8, parsed_sub, c_sub) && c_sub == 8) {
                        const u16 sub_vid = static_cast<u16>(parsed_sub & 0xFFFFu);
                        const u32 sub_did = static_cast<u32>((parsed_sub >> 16) & 0xFFFFu);
                        add_device(sub_vid, sub_did);
                    }
                }
            };

            HDEVINFO h_dev_info = SetupDiGetClassDevsW(
                nullptr,
                nullptr,
                nullptr,
                DIGCF_ALLCLASSES | DIGCF_PRESENT
            );

            if (h_dev_info != INVALID_HANDLE_VALUE) {
                SP_DEVINFO_DATA dev_info_data{};
                dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

                for (DWORD i = 0; SetupDiEnumDeviceInfo(h_dev_info, i, &dev_info_data); ++i) {
                    DWORD reg_type = 0;
                    DWORD required_size = 0;

                    SetupDiGetDeviceRegistryPropertyW(
                        h_dev_info,
                        &dev_info_data,
                        SPDRP_HARDWAREID,
                        &reg_type,
                        nullptr,
                        0,
                        &required_size
                    );

                    if (required_size == 0 || required_size > MAX_MULTI_SZ) {
                        continue;
                    }

                    static thread_local std::vector<wchar_t> buf;
                    const size_t aligned_size = (required_size + sizeof(wchar_t) - 1) & ~(sizeof(wchar_t) - 1);
                    const size_t needed_wchars = aligned_size / sizeof(wchar_t);
                    const size_t total_wchars_needed = needed_wchars + 2;

                    buf.assign(total_wchars_needed, L'\0');

                    if (SetupDiGetDeviceRegistryPropertyW(
                        h_dev_info,
                        &dev_info_data,
                        SPDRP_HARDWAREID,
                        &reg_type,
                        reinterpret_cast<PBYTE>(buf.data()),
                        static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                        nullptr
                    )) {
                        if (reg_type == REG_MULTI_SZ) {
                            buf[needed_wchars] = L'\0';
                            buf[needed_wchars + 1] = L'\0';

                            for (wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) {
                                VMAWARE_PREFETCH(p + 32, _MM_HINT_T0);
                                scan_text_ids(p);
                            }
                        }
                    }
                }
                SetupDiDestroyDeviceInfoList(h_dev_info);
            }
        #endif

        for (const auto d : devices) {
            const u64 id64 = (static_cast<u64>(d.vendor_id) << 32) | d.device_id;
            const u32 id32 = (static_cast<u32>(d.vendor_id) << 16) | static_cast<u32>(d.device_id);

            switch (id32) {
                /* Red Hat + Virtio */
                case 0x1af40022: case 0x1af41000: case 0x1af41001: case 0x1af41002:
                case 0x1af41003: case 0x1af41004: case 0x1af41005: case 0x1af41009:
                case 0x1af41041: case 0x1af41042: case 0x1af41043: case 0x1af41044:
                case 0x1af41045: case 0x1af41048: case 0x1af41049: case 0x1af41050:
                case 0x1af41052: case 0x1af41053: case 0x1af4105a: case 0x1af41100:
                case 0x1af41110: case 0x1af41b36:
                    vma_debug("DEVICES: Detected Red Hat + Virtio device -> 0x", std::hex, id32);
                    return true;

                /* VMware */
                case 0x15ad0710: case 0x15ad0720: case 0x15ad0770: case 0x15ad0774: 
                case 0x15ad0778: case 0x15ad0779: case 0x15ad0790: case 0x15ad07a0: 
                case 0x15ad07b0: case 0x15ad07c0: case 0x15ad07e0: case 0x15ad07f0: 
                case 0x15ad0801: case 0x15ad0820: case 0x15ad1977: case 0xfffe0710: 
                case 0x0e0f0001: case 0x0e0f0002: case 0x0e0f0003: case 0x0e0f0004: 
                case 0x0e0f0005: case 0x0e0f0006: case 0x0e0f000a: case 0x0e0f8001: 
                case 0x0e0f8002: case 0x0e0f8003: case 0x0e0ff80a:
                    vma_debug("DEVICES: Detected VMWARE device -> 0x", std::hex, id32);
                    return core::add(brand_enum::VMWARE);

                /* Red Hat + QEMU */
                case 0x1b360001: case 0x1b360002: case 0x1b360003: case 0x1b360004:
                case 0x1b360005: case 0x1b360008: case 0x1b360009: case 0x1b36000b:
                case 0x1b36000c: case 0x1b36000d: case 0x1b360010: case 0x1b360011:
                case 0x1b360013: case 0x1b360100:
                    vma_debug("DEVICES: Detected Red Hat + QEMU device -> 0x", std::hex, id32);
                    return core::add(brand_enum::QEMU);

                /* QEMU */
                case 0x06270001: case 0x1d1d1f1f: case 0x80865845: case 0x1d6b0200:
                    vma_debug("DEVICES: Detected QEMU device -> 0x", std::hex, id32);
                    return core::add(brand_enum::QEMU);

                /* VGPUs (NVIDIA + others) */
                case 0x10de0fe7: case 0x10de0ff7: case 0x10de118d: case 0x10de11b0:
                case 0x1ec6020f:
                    vma_debug("DEVICES: Detected virtual gpu device -> 0x", std::hex, id32);
                    return true;

                /* VirtualBox */
                case 0x80ee0021: case 0x80ee0022: case 0x80eebeef: case 0x80eecafe:
                    vma_debug("DEVICES: Detected VirtualBox device -> 0x", std::hex, id32);
                    return core::add(brand_enum::VBOX);

                /* Parallels */
                case 0x1ab84000: case 0x1ab84005: case 0x1ab84006:
                    vma_debug("DEVICES: Detected Parallels device -> 0x", std::hex, id32);
                    return core::add(brand_enum::PARALLELS);

                /* Xen */
                case 0x5853c000: case 0xfffd0101: case 0x5853c147:
                case 0x5853c110: case 0x5853c200: case 0x58530001:
                    vma_debug("DEVICES: Detected Xen device -> 0x", std::hex, id32);
                    return core::add(brand_enum::XEN);

                /* Connectix (VirtualPC) */
                case 0x29556e61:
                    vma_debug("DEVICES: Detected VirtualPC device -> 0x", std::hex, id32);
                    return core::add(brand_enum::VPC);
            }

            /* Devices with 32 bit device ids */
            switch (id64) {
                case 0x0000000011061100ULL:
                case 0x000000001af41100ULL:
                case 0x000000001b361100ULL:
                case 0x0000000010ec1100ULL:
                case 0x0000000010331100ULL:
                case 0x0000000080861100ULL:
                case 0x0000000010131100ULL:
                case 0x00000000106b1100ULL:
                case 0x0000000010221100ULL:
                    vma_debug("DEVICES: Detected QEMU device -> 0x", std::hex, id64);
                    return core::add(brand_enum::QEMU);
    
                case 0x0000000015ad0800ULL:  /* Hypervisor ROM Interface */
                    vma_debug("DEVICES: Detected Hypervisor ROM interface -> 0x", std::hex, id64);
                    return core::add(brand_enum::VMWARE);
            }
        }
        
        return false;
    }


    /**
     * @brief Check boot logo for known VM images
     * @category Windows, Linux, x86_64
     * @author Teselka (https://github.com/Teselka)
     * @implements VM::BOOT_LOGO
     */
    [[nodiscard]] static bool boot_logo()
    #if (VMAWARE_X86 && (VMAWARE_CLANG || VMAWARE_GCC))
        __attribute__((__target__("crc32")))
    #endif
    {
    #if (VMAWARE_X86_64)       
        #if (VMAWARE_WINDOWS)
            const HMODULE ntdll = memory::get_module(true);
            if (!ntdll) {
                return false;
            }

            const char* function_names[] = { "NtQuerySystemInformation" };
            void* functions[ARRAYSIZE(function_names)] = {};
            memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

            using nt_query_sysinfo_fn = NTSTATUS(__stdcall*)(ULONG, PVOID, ULONG, PULONG); /* int is SYSTEM_INFORMATION_CLASS */
            nt_query_sysinfo_fn nt_query_system_information = reinterpret_cast<nt_query_sysinfo_fn>(functions[0]);
            if (!nt_query_system_information) {
                return false;
            }

            /* Parse header to locate the bitmap */
            struct boot_logo_info { ULONG flags, bitmap_offset; };

            const int sys_boot_info = 140; /* SystemBootLogoInformation */
            ULONG needed = 0;
            NTSTATUS st = nt_query_system_information(sys_boot_info, nullptr, 0, &needed);
            if (st != static_cast<NTSTATUS>(0xC0000023) &&
                st != static_cast<NTSTATUS>(0x80000005) &&
                st != static_cast<NTSTATUS>(0xC0000004)) { 
                return false;
            }
            std::vector<u8> buffer(needed);

            /* Fetch the boot-logo data */
            st = nt_query_system_information(sys_boot_info, buffer.data(), needed, &needed);
            if (!NT_SUCCESS(st)) {
                return false;
            }

            if (needed < sizeof(boot_logo_info)) {
                return false;
            }

            const auto* info = reinterpret_cast<const boot_logo_info*>(buffer.data());
            if (info->bitmap_offset >= needed) {
                return false;
            }

            const u8* bmp = buffer.data() + info->bitmap_offset;
            const size_t size = static_cast<size_t>(needed) - info->bitmap_offset;
        #else
            const int fd = open("/sys/firmware/acpi/bgrt/image", O_RDONLY);
            if (fd < 0) {
                vma_debug("BOOT_LOGO: failed to open /sys/firmware/acpi/bgrt/image");
                return false;
            }

            const off_t size = lseek(fd, 0, SEEK_END);
            if (size <= 0) {
                vma_debug("BOOT_LOGO: failed to seek to the end");
                close(fd);
                return false;
            }

            lseek(fd, 0, SEEK_SET);

            std::vector<u8> buffer(size);
            ssize_t read_size = 0;
            size_t off = 0;
            for (;;) {
                read_size = read(fd, buffer.data() + off, size - off);
                if (read_size <= 0) { 
                    break; 
                }
                off += static_cast<size_t>(read_size);
                if (off >= static_cast<size_t>(size)) { 
                    break; 
                }
            }

            close(fd);
            if (off != static_cast<size_t>(size)) {
                vma_debug("BOOT_LOGO: read failed or partial");
                return false;
            }

            const u8* bmp = buffer.data();
        #endif

        const u32 hash = util::hash::crc32c(0xFFFFFFFFu, bmp, size) ^ 0xFFFFFFFFu;

        #if (VMAWARE_WINDOWS)
            vma_debug("BOOT_LOGO: size=", needed, ", flags=", info->flags, ", offset=", info->bitmap_offset, ", crc=0x", std::hex, hash);
        #else
            vma_debug("BOOT_LOGO: size=", size, ", crc=0x", std::hex, hash);
        #endif

        switch (hash) {
            case 0x110350C5: return core::add(brand_enum::QEMU); /* TianoCore EDK2 */
            case 0x87c39681: return core::add(brand_enum::HYPERV);
            default:         return false;
        }
    #else
        return false;
    #endif
    }

    
    /**
    * @brief Check for presence of virtual disks
    * @category Windows
    * @implements VM::DISK
    */
    [[nodiscard]] static bool disk() {
        bool result = false;

        /*
         * Helper to detect QEMU instances based on default hard drive serial patterns
         * QEMU drives often start with "QM000" followed by digits
         */
        auto is_qemu_serial = [](const char* str, const size_t len) noexcept -> bool {
            if (!str || len < 6) {
                return false;
            }
            return (string::to_lower(str[0]) == 'q' &&
                string::to_lower(str[1]) == 'm' &&
                string::starts_with(str + 2, "0000"));
        };

        /*
         * Helper to detect VirtualBox instances
         * VirtualBox uses a specific serial format "VB" followed by hex segments
         */
        auto is_vbox_serial = [](const char* str, const size_t len) noexcept -> bool {
            /* Format: VB12345678-12345678 (19 chars) */
            if (len != 19 || !str) {
                return false;
            }

            if (string::to_lower(str[0]) != 'v' || string::to_lower(str[1]) != 'b') {
                return false;
            }
            if (str[10] != '-') {
                return false;
            }

            for (size_t i = 2; i < 10; ++i) {
                if (!string::is_hex(str[i])) {
                    return false;
                }
            }

            for (size_t i = 11; i < 19; ++i) {
                if (!string::is_hex(str[i])) {
                    return false;
                }
            }

            return true;
        };

    #if (VMAWARE_WINDOWS)

        #ifndef StorageAdapterProtocolSpecificProperty
            #define StorageAdapterProtocolSpecificProperty static_cast<STORAGE_PROPERTY_ID>(49)
        #endif
        #ifndef StorageDeviceProtocolSpecificProperty
            #define StorageDeviceProtocolSpecificProperty static_cast<STORAGE_PROPERTY_ID>(50)
        #endif

        auto strnlen = [](const char* s, const size_t max) noexcept -> size_t {
            const void* p = std::memchr(s, 0, max);
            if (!p) {
                return max;
            }
            return static_cast<size_t>(static_cast<const char*>(p) - s);
        };

        constexpr u16 MAX_PHYSICAL_DRIVES = 256;
        constexpr size_t MAX_DESCRIPTOR_SIZE = 64 * 1024;
        u8 successful_opens = 0;

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return result;
        }

        constexpr const char* function_names[] = {
            "RtlInitUnicodeString",
            "NtOpenFile",
            "NtDeviceIoControlFile",
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtFlushInstructionCache",
            "NtClose"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using ntopenfile_fn = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
        using nt_device_io_control_file_fn = NTSTATUS(__stdcall*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using ntclose_fn = NTSTATUS(__stdcall*)(HANDLE);
        using rtl_init_unicode_string_fn = void(__stdcall*)(PUNICODE_STRING, PCWSTR);

        const auto rtl_init_unicode_string = reinterpret_cast<rtl_init_unicode_string_fn>(functions[0]);
        const auto nt_open_file = reinterpret_cast<ntopenfile_fn>(functions[1]);
        const auto nt_device_io_control_file = reinterpret_cast<nt_device_io_control_file_fn>(functions[2]);
        const auto nt_allocate_virtual_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[3]);
        const auto nt_free_virtual_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[4]);
        const auto nt_close = reinterpret_cast<ntclose_fn>(functions[6]);

        if (!rtl_init_unicode_string || !nt_open_file || !nt_device_io_control_file ||
            !nt_allocate_virtual_memory || !nt_free_virtual_memory || !nt_close) {
            return result;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);

        /* NVMe heuristic checks */     
        auto check_nvme_heuristics = [&](HANDLE dev) noexcept -> bool {
        #pragma pack(push, 1)
            struct ProtocolQuery {
                STORAGE_PROPERTY_QUERY query;
                struct {
                    DWORD ProtocolType;
                    DWORD DataType;
                    DWORD ProtocolDataRequestValue;
                    DWORD ProtocolDataRequestSubValue;
                    DWORD ProtocolDataOffset;
                    DWORD ProtocolDataLength;
                    DWORD FixedProtocolReturnData;
                    DWORD Reserved[3];
                } protocol_data;
            } qpacket{};
        #pragma pack(pop)

            auto query_protocol = [&](const STORAGE_PROPERTY_ID prop_id, const DWORD data_type, const DWORD req_val, const DWORD req_sub_val, void* out_buf, const DWORD out_size) noexcept -> bool {
                qpacket.query.PropertyId = prop_id;
                qpacket.query.QueryType = PropertyStandardQuery;
                qpacket.protocol_data.ProtocolType = ProtocolTypeNvme;
                qpacket.protocol_data.DataType = data_type;
                qpacket.protocol_data.ProtocolDataRequestValue = req_val;
                qpacket.protocol_data.ProtocolDataRequestSubValue = req_sub_val;
                qpacket.protocol_data.ProtocolDataOffset = sizeof(qpacket.protocol_data);
                qpacket.protocol_data.ProtocolDataLength = out_size;

                const size_t header_size = sizeof(ProtocolQuery);
                const size_t total_size = header_size + out_size;

                PVOID allocation_base = nullptr;
                SIZE_T region_size = total_size;
                NTSTATUS query_st = nt_allocate_virtual_memory(current_process, &allocation_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!NT_SUCCESS(query_st) || allocation_base == nullptr) {
                    return false;
                }

                RtlZeroMemory(allocation_base, total_size);
                *reinterpret_cast<ProtocolQuery*>(allocation_base) = qpacket;

                IO_STATUS_BLOCK query_iosb{};
                query_st = nt_device_io_control_file(dev, nullptr, nullptr, nullptr, &query_iosb,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    allocation_base, static_cast<ULONG>(total_size),
                    allocation_base, static_cast<ULONG>(total_size));

                bool success = false;
                if (NT_SUCCESS(query_st)) {
                    BYTE* payload = reinterpret_cast<BYTE*>(allocation_base) + header_size;
                    if (query_iosb.Information >= header_size + out_size) {
                        std::memcpy(out_buf, payload, out_size);
                        success = true;
                    }   
                }

                SIZE_T free_size = 0;
                nt_free_virtual_memory(current_process, &allocation_base, &free_size, MEM_RELEASE);
                return success;
            };

            /* Verify dynamic virtualization & mamespace support without device self-test support */
            BYTE identify_ctrl[4096];
            RtlZeroMemory(identify_ctrl, sizeof(identify_ctrl));
            if (query_protocol(StorageAdapterProtocolSpecificProperty, 1, 0x01, 0, identify_ctrl, sizeof(identify_ctrl))) {
                const u16 oacs = *reinterpret_cast<const u16*>(&identify_ctrl[256]);
                const bool supports_virtualization_mgmt = (oacs & (1 << 8)) != 0;
                const bool supports_namespace_mgmt = (oacs & (1 << 3)) != 0;
                const bool lacks_self_test = (oacs & (1 << 4)) == 0;

                if (supports_virtualization_mgmt && supports_namespace_mgmt && lacks_self_test) {
                    vma_debug("NVME_HEURISTIC: Virtual OACS signature detected");
                    return true;
                }
            }

            /* Verify if the drive supports exactly 8 formats containing metadata, enabled logical sectors  */
            BYTE identify_ns[4096];
            RtlZeroMemory(identify_ns, sizeof(identify_ns));
            if (query_protocol(StorageDeviceProtocolSpecificProperty, 1, 0x00, 1, identify_ns, sizeof(identify_ns))) {
                const u8 nlbaf = identify_ns[25]; /* Number of LBA Formats (0 - based) */
                if (nlbaf == 7) { /* 8 available formats */
                    bool has_metadata_option = false;
                    for (int i = 0; i < 8; ++i) {
                        const size_t entry_offset = 128 + (static_cast<size_t>(i) * 4); /* LBA Format Table starts at offset 128 */
                        const u16 ms = *reinterpret_cast<const u16*>(&identify_ns[entry_offset]);
                        if (ms != 0) {
                            has_metadata_option = true;
                            break;
                        }
                    }
                    if (has_metadata_option) {
                        vma_debug("NVME_HEURISTIC: Synthetic LBA structure with metadata option detected");
                        return core::add(brand_enum::QEMU);
                    }
                }
            }

            return false;
        };

        /* Iterate through all physical drives, we put 256 as the physical limit */
        for (u16 drive = 0; drive < MAX_PHYSICAL_DRIVES; ++drive) {
            wchar_t path[32];
            swprintf_s(path, L"\\??\\PhysicalDrive%u", drive);

            UNICODE_STRING unicode_path;
            rtl_init_unicode_string(&unicode_path, path);

            OBJECT_ATTRIBUTES object_attributes;
            RtlZeroMemory(&object_attributes, sizeof(object_attributes));
            object_attributes.Length = sizeof(object_attributes);
            object_attributes.ObjectName = &unicode_path;
            object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
            object_attributes.RootDirectory = nullptr;

            IO_STATUS_BLOCK iosb;
            HANDLE device = nullptr;

            constexpr ACCESS_MASK desired_access = SYNCHRONIZE | FILE_READ_ATTRIBUTES;
            constexpr ULONG share_access = FILE_SHARE_READ | FILE_SHARE_WRITE;
            constexpr ULONG open_options = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

            /* Attempt to open the physical drive directly using Native API */
            NTSTATUS st = nt_open_file(&device, desired_access, &object_attributes, &iosb, share_access, open_options);
            if (!NT_SUCCESS(st) || device == nullptr) {
                continue;
            }
            ++successful_opens;

            /* Run NVMe heuristics first */
            if (check_nvme_heuristics(device)) {
                nt_close(device);
                return true;
            }

            /*
             * Stack buffer attempt
             * we first try to read the storage properties into a small stack buffer to avoid heap
             */
            BYTE stack_buffer[512] = { 0 };
            const STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(stack_buffer);

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            const ULONG ioctl = IOCTL_STORAGE_QUERY_PROPERTY;

            st = nt_device_io_control_file(device, nullptr, nullptr, nullptr, &iosb,
                ioctl,
                &query, sizeof(query),
                stack_buffer, sizeof(stack_buffer));

            BYTE* allocated_buffer = nullptr;
            SIZE_T allocated_size = 0;

            /*
             * If the stack buffer was too small (NtDeviceIoControlFile failed), we fall back
             * to allocating memory dynamically using NtAllocateVirtualMemory
             */
            if (!NT_SUCCESS(st)) {
                DWORD reported_size = 0;
                if (descriptor && descriptor->Size > 0) {
                    reported_size = descriptor->Size;
                }

                /* This branch just ensures the requested size is reasonable before allocating */
                if (reported_size > 0 && reported_size < static_cast<DWORD>(MAX_DESCRIPTOR_SIZE) && reported_size >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                    allocated_size = static_cast<SIZE_T>(reported_size);
                    PVOID allocation_base = nullptr;
                    SIZE_T region_size = allocated_size;
                    st = nt_allocate_virtual_memory(current_process, &allocation_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (!NT_SUCCESS(st) || allocation_base == nullptr) {
                        nt_close(device);
                        continue;
                    }
                    allocated_buffer = reinterpret_cast<BYTE*>(allocation_base);

                    /* Retry the query with the larger allocated buffer */
                    st = nt_device_io_control_file(device, nullptr, nullptr, nullptr, &iosb, ioctl, &query, sizeof(query), allocated_buffer, static_cast<ULONG>(allocated_size));
                    if (!NT_SUCCESS(st)) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = 0;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        nt_close(device);
                        continue;
                    }
                    descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(allocated_buffer);
                }
                else {
                    nt_close(device);
                    continue;
                }
            }

            /* Determine the physical boundary of the buffer currently in use */
            const size_t current_buffer_size = allocated_buffer ? allocated_size : sizeof(stack_buffer);

            /* This part is just to validate the structure size returned by the driver to prevent out-of-bounds reads */
            {
                const DWORD reported_size = descriptor->Size;
                if (reported_size < sizeof(STORAGE_DEVICE_DESCRIPTOR) ||
                    static_cast<SIZE_T>(reported_size) > MAX_DESCRIPTOR_SIZE ||
                    static_cast<SIZE_T>(reported_size) > current_buffer_size) { // Bound reported size to current physical buffer size
                    if (allocated_buffer) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = 0;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        allocated_buffer = nullptr;
                    }
                    nt_close(device);
                    continue;
                }
            }

            /* Restrict validation and scanning limits strictly to the active initialized portion */
            const size_t active_size = (static_cast<size_t>(descriptor->Size) < current_buffer_size)
                ? static_cast<size_t>(descriptor->Size)
                : current_buffer_size;

            /* Serial number string within the descriptor structure */
            const u32 serial_offset = descriptor->SerialNumberOffset;
            if (serial_offset > 0 && static_cast<size_t>(serial_offset) < active_size) {
                const char* serial = reinterpret_cast<const char*>(descriptor) + serial_offset;
                const size_t max_avail = active_size - static_cast<size_t>(serial_offset);
                const size_t serialLen = strnlen(serial, max_avail);

                vma_debug("DISK_SERIAL: ", serial);

                /* Check the retrieved serial number against known VM artifacts */
                if (is_qemu_serial(serial, serialLen) || is_vbox_serial(serial, serialLen)) {
                    if (allocated_buffer) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = 0;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        allocated_buffer = nullptr;
                    }
                    nt_close(device);
                    return true;
                }
            }

            /* Cleanup for the current iteration if no VM was detected on this drive */
            if (allocated_buffer) {
                PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                SIZE_T free_size = 0;
                nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                allocated_buffer = nullptr;
            }
            nt_close(device);
        }

        /* If we couldn't open any physical drives (not even read permissions) it's weird so we flag it. */
        if (successful_opens == 0) {
            vma_debug("DISK_SERIAL: No physical drives detected");
            return true;
        }
    #else
        struct DirDeleter {
            void operator()(DIR* d) const {
                if (d != nullptr) {
                    closedir(d);
                }
            }
        };

        std::unique_ptr<DIR, DirDeleter> dir(opendir("/sys/block"));
        if (!dir) {
            return false;
        }

        struct dirent* ent{};

        while ((ent = readdir(dir.get()))) {
            const char* name = ent->d_name;
            if (name[0] == '.') {
                continue;
            }

            if (string::starts_with(name, "nvme") ||
                string::starts_with(name, "sd") ||
                string::starts_with(name, "sg") ||
                string::starts_with(name, "hd") ||
                string::starts_with(name, "vd")) {
                const char sys_block_str[] = "/sys/block/";
                const char device_serial_str[] = "/device/serial";

                /* /sys/block/%s/device/serial */
                char buf[sizeof(dirent::d_name) + sizeof(sys_block_str) + sizeof(device_serial_str)];
                snprintf(buf, sizeof(buf), "%s%s%s", sys_block_str, name, device_serial_str);

                const int fd = open(buf, O_RDONLY);
                if (fd < 0) {
                    continue;
                }

                char serial[1024] = {};
                const ssize_t rsize = read(fd, serial, sizeof(serial) - 1);
                close(fd);
                if (rsize < 0) {
                    continue;
                }

                vma_debug("DISK_SERIAL: ", (const char*)serial);
                if (is_qemu_serial(serial, static_cast<size_t>(rsize)) || is_vbox_serial(serial, static_cast<size_t>(rsize))) {
                    result = true;
                }
            }
        }

        dir.reset();
    #endif
        return result;
    }
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
    #pragma region "Linux and Apple"
#endif

#if (VMAWARE_LINUX || VMAWARE_APPLE)
    /**
     * @brief Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings, nowadays physical CPUs should have at least 4 threads for modern CPUs
     * @category x86 (ARM might have very low thread counts, which is why it should be only for x86)
     * @implements VM::THREAD_COUNT
     */
    [[nodiscard]] static bool thread_count() {
    #if (VMAWARE_X86 && !VMAWARE_APPLE)
        vma_debug("THREAD_COUNT: ", "threads = ", memo::thread_count::fetch());

        const struct cpu::stepping_struct steps = cpu::fetch_steppings();

        if (cpu::is_celeron(steps)) {
            return false;
        }

        return (memo::thread_count::fetch() <= 2);
    #else 
        return false;
    #endif
    }
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
    #pragma region "Apple"
#endif

#if (VMAWARE_APPLE) 
    /**
     * @brief Check if the sysctl for the hwmodel does not contain the "Mac" string
     * @author MacRansom ransomware
     * @category MacOS
     * @implements VM::HWMODEL
     */
    [[nodiscard]] static bool hwmodel() {
        
        /* Hw.model strings are short (like for example MacBookPro16,1), 128 bytes is plenty */
        char buffer[128] = { 0 };
        size_t size = sizeof(buffer);

        /*
         * Sysctlbyname queries the kernel directly, bypassing the overhead of
         * fork(), exec(), and pipe() found in util::sys_result (popen)
         */
        if (sysctlbyname("hw.model", buffer, &size, nullptr, 0) != 0) {
            vma_debug("HWMODEL: ", "failed to read hw.model");
            return false;
        }

        buffer[127] = '\0';

        /*
         * Sysctlbyname returns the raw value (usually without a trailing newline),
         * so no trimming is required
         */
        vma_debug("HWMODEL: ", "output = ", buffer);

        if (strstr(buffer, "Mac") != nullptr) {
            return false;
        }

        if (strstr(buffer, "VMware") != nullptr) {
            return core::add(brand_enum::VMWARE);
        }

        /* Assumed true since it doesn't contain "Mac" string */
        return true;
    }


    /**
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_MEMSIZE
     */
    [[nodiscard]] static bool hw_memsize() {
        std::unique_ptr<std::string> result = util::sys_result("sysctl -n hw.memsize");
        const std::string ram = *result;

        if (ram == "0") {
            return false;
        }

        vma_debug("MAC_MEMSIZE: ", "ram size = ", ram);

        if (!string::is_numeric(ram)) {
            vma_debug("MAC_MEMSIZE: ", "found non-digit character, returned false");
            return false;
        }

        const u64 ram_u64 = std::stoull(ram);

        vma_debug("MAC_MEMSIZE: ", "ram size in u64 = ", ram_u64);

        constexpr u64 limit = 4000000000; /* 4GB */

        return (ram_u64 <= limit);
    }


    /**
     * @brief Check MacOS' IO kit registry for VM-specific strings
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_IOKIT
     */
    [[nodiscard]] static bool io_kit() {
        /* Board_ptr and manufacturer_ptr empty */
        std::unique_ptr<std::string> platform_ptr = util::sys_result("ioreg -rd1 -c IOPlatformExpertDevice");
        std::unique_ptr<std::string> board_ptr = util::sys_result("ioreg -rd1 -c board-id");
        std::unique_ptr<std::string> manufacturer_ptr = util::sys_result("ioreg -rd1 -c manufacturer");
        std::unique_ptr<std::string> keyboard_ptr = util::sys_result("ioreg -lw0 -p IODeviceTree");

        const std::string platform = *platform_ptr;
        const std::string board = *board_ptr;
        const std::string manufacturer = *manufacturer_ptr;
        const std::string keyboard = *keyboard_ptr;

        auto check_platform = [&]() noexcept -> bool {
            vma_debug("IO_KIT: ", "platform = ", platform);

            if (platform.empty()) {
                return false;
            }

            for (const char c : platform) {
                if (!std::isdigit(c)) {
                    return false;
                }
            }

            return (platform == "0");
        };

        auto check_board = [&]() noexcept -> bool {
            vma_debug("IO_KIT: ", "board = ", board);

            if (board.empty()) {
                return false;
            }

            if (util::find(board, "Mac")) {
                return false;
            }

            if (util::find(board, "VirtualBox")) {
                return core::add(brand_enum::VBOX);
            }

            if (util::find(board, "VMware")) {
                return core::add(brand_enum::VMWARE);
            }

            return false;
        };

        auto check_manufacturer = [&]() noexcept -> bool {
            vma_debug("IO_KIT: ", "manufacturer = ", manufacturer);

            if (manufacturer.empty()) {
                return false;
            }

            if (util::find(manufacturer, "Apple")) {
                return false;
            }

            if (util::find(manufacturer, "innotek")) {
                return core::add(brand_enum::VBOX);
            }

            return false;
        };

        auto check_keyboard = [&]() noexcept -> bool {
            vma_debug("IO_KIT: ", "keyboard = ", keyboard);

            if (keyboard.empty()) {
                return false;
            }

            if (util::find(keyboard, "Virtual Machine")) {
                return true;
            }

            return false;
        };

        return (
            check_platform() ||
            check_board() ||
            check_manufacturer() ||
            check_keyboard()
       );
    }


    /**
     * @brief Check for VM-strings in ioreg commands for MacOS
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::IOREG_GREP
     */
    [[nodiscard]] static bool ioreg_grep() {
        auto check_usb = []() -> bool {
            std::unique_ptr<std::string> result = util::sys_result("ioreg -rd1 -c IOUSBHostDevice | grep \"USB Vendor Name\"");
            const std::string usb = *result;

            if (util::find(usb, "Apple")) {
                return false;
            }

            if (util::find(usb, "VirtualBox")) {
                return core::add(brand_enum::VBOX);
            }

            return false;
        };

        auto check_rom = []() -> bool {
            std::unique_ptr<std::string> sys_rom = util::sys_result("system_profiler SPHardwareDataType | grep \"Boot ROM Version\"");
            const std::string rom = *sys_rom;

            if (util::find(rom, "VirtualBox")) {
                return core::add(brand_enum::VBOX);
            }

            return false;
        };

        return (
            check_usb() ||
            check_rom()
        );
    }


    /**
     * @brief Check for the status of System Integrity Protection and hv_mm_present
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_SIP
     */
    [[nodiscard]] static bool mac_sip() {
        int hv_present = 0;
        std::size_t size = sizeof(hv_present);
        if (sysctlbyname("kern.hv_vmm_present",
            &hv_present,
            &size,
            nullptr,
            0) != 0) {
            return false;
        }

        if (hv_present != 0) {
            return true;
        }

        std::unique_ptr<std::string> result = util::sys_result("csrutil status");

        if (!result) {
            return false;
        }

        std::string tmp = *result;

        auto pos = tmp.find('\n');

        if (pos != std::string::npos) {
            tmp.resize(pos);
        }

        vma_debug("MAC_SIP: ", "result = ", tmp);

        if (util::find(tmp, "unknown")) {
            return false;
        }

        return (util::find(tmp, "disabled"));
    }


    /**
     * @brief Check for VM-strings in system profiler commands for MacOS
     * @category MacOS
     * @implements VM::MAC_SYS
     */
    [[nodiscard]] static bool mac_sys() {
        const char* keyword = "virtual machine";

        if (std::unique_ptr<std::string> profiler_res_ptr = util::sys_result("system_profiler SPHardwareDataType")) {
            std::string& output = *profiler_res_ptr;
            string::to_lower_inplace(output);

            if (util::find(output, keyword)) {
                return true;
            }
        }

        return false;
    }
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
#endif

#if (VMAWARE_MSVC)
    #pragma region "Windows"
#endif

#if (VMAWARE_WINDOWS)
    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     * @implements VM::DLL
     */
    [[nodiscard]] static bool dll() {
        static constexpr struct {
            const wchar_t* dll_name;
            enum brand_enum brand;
        } dlls[] = {
            {L"sbiedll.dll",   brand_enum::SANDBOXIE},
            {L"pstorec.dll",   brand_enum::CWSANDBOX},
            {L"vmcheck.dll",   brand_enum::VPC},
            {L"cmdvrt32.dll",  brand_enum::COMODO},
            {L"cmdvrt64.dll",  brand_enum::COMODO},
            {L"cuckoomon.dll", brand_enum::CUCKOO},
            {L"SxIn.dll",      brand_enum::QIHOO},
            {L"wpespy.dll",    brand_enum::NULL_BRAND}
        };

        for (const auto& x : dlls) {
            if (GetModuleHandleW(x.dll_name) != nullptr) {
                vma_debug("DLL: Found ", x.dll_name, " (", brands::brand_enum_to_string(x.brand), ")");
                return core::add(x.brand);
            }
        }

        return false;
    }

             
    /**
     * @brief Check for Wine Is Not An Emulator artifacts
     * @category Windows
     * @implements VM::WINE
     */
    [[nodiscard]] static bool wine() {
        const HMODULE kernel32 = memory::get_module(false);
        if (!kernel32) {
            return false;
        }

        BOOL is_wow64_process;
        BOOL ok = IsWow64Process(GetCurrentProcess(), &is_wow64_process);
        if (!ok) {
            vma_debug("WINE: IsWow64Process failed");
            return false;
        }
        int expected_value = is_wow64_process ? 2 : -1;
        if (MulDiv(1,INT_MIN,INT_MIN) != expected_value) {
            vma_debug("WINE: Unexpected MulDiv result detected");
            return core::add(brand_enum::WINE);
        }

        using wine_get_unix_file_name_fn = char* (__stdcall*)(const wchar_t*, char*, DWORD);
        auto wine_get_unix_file = reinterpret_cast<wine_get_unix_file_name_fn>(GetProcAddress(kernel32, "wine_get_unix_file_name"));
        if (wine_get_unix_file != nullptr) {
            vma_debug("WINE: wine_get_unix_file_name detected");
            return core::add(brand_enum::WINE);
        }

    #if (_WIN32_WINNT > _WIN32_WINNT_WIN8)
        if (util::is_windows_8_or_newer()) {
            using is_native_vhd_boot_fn = BOOL(__stdcall*)(PBOOL);
            auto is_native_vhd_boot = reinterpret_cast<is_native_vhd_boot_fn>(GetProcAddress(kernel32, "IsNativeVhdBoot"));

            if (is_native_vhd_boot) {
                BOOL is_vhd = FALSE;
                __try {
                    /*
                     * We dont call NtQuerySystemInformation with SystemPrefetchPathInformation | SystemHandleInformation
                     * the point is to check if this kernel32.dll function throws an exception
                     */
                    is_native_vhd_boot(&is_vhd);
                    return is_vhd;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    vma_debug("WINE: IsNativeVhdBoot threw an exception (Wine stub behavior)");
                    return core::add(brand_enum::WINE);
                }
            }
            else {
                vma_debug("WINE: IsNativeVhdBoot export missing in Win8+ environment");
                return core::add(brand_enum::WINE);
            }
        }
    #endif

        return false;
    }


    /**
     * @brief Check what power states are enabled
     * @category Windows
     * @implements VM::POWER_CAPABILITIES
     */
    [[nodiscard]] static bool power_capabilities() {
        const HMODULE ntdll = memory::get_module(true);

        constexpr const char* function_names[] = { "NtPowerInformation" }; /* Win8 // Windows Server 2012 */
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));
        if (!functions[0]) {
            return false;
        }

        using nt_power_information_fn = NTSTATUS(__stdcall*)(POWER_INFORMATION_LEVEL, PVOID, ULONG, PVOID, ULONG);
        const auto nt_power_information = reinterpret_cast<nt_power_information_fn>(functions[0]);

        SYSTEM_POWER_CAPABILITIES caps{};
        const NTSTATUS status = nt_power_information(SystemPowerCapabilities, nullptr, 0, &caps, sizeof(caps));
        if (status != 0) {
            return false;
        }
        const bool s0_supported = caps.AoAc;
        const bool s1_supported = caps.SystemS1;
        const bool s2_supported = caps.SystemS2;
        const bool s3_supported = caps.SystemS3;
        const bool s4_supported = caps.SystemS4;
        const bool hiber_file_present = caps.HiberFilePresent;

        const bool is_physical_pattern = (s0_supported || s3_supported) && (s4_supported || hiber_file_present);

        if (is_physical_pattern) {
            return false;
        }

        const bool is_vm_pattern = !(s0_supported || s3_supported || s4_supported || hiber_file_present) &&
            (s1_supported || s2_supported);

        if (is_vm_pattern) {
            vma_debug("POWER_CAPABILITIES: Detected !(S0||S3||S4||HiberFilePresent) + S1|S2 pattern");
            return true;
        }

        /* Could check for HKLM\SYSTEM\CurrentControlSet\Control\Power\PlatformAoAcOverride */
        const bool no_sleep_states = !s0_supported && !s1_supported && !s2_supported && !s3_supported && !s4_supported && !hiber_file_present;
        if (no_sleep_states) {
            vma_debug("POWER_CAPABILITIES: Detected !(S0||S1||S2||S3||S4||H) pattern");
            return true;
        }

        return false;
    }


    /**
     * @brief Check for Gamarue ransomware technique which compares VM-specific Window product IDs
     * @category Windows
     * @implements VM::GAMARUE
     */
    [[nodiscard]] static bool gamarue() {
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtOpenKey", "NtQueryValueKey", "RtlInitUnicodeString", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(functions[0]);
        const auto nt_query_value_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG)>(functions[1]);
        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(functions[2]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[3]);

        if (!nt_open_key || !nt_query_value_key || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        UNICODE_STRING key_name;
        rtl_init_unicode_string(&key_name, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");

        OBJECT_ATTRIBUTES object_attributes;
        ZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &key_name;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        /* Open the registry key with minimal permissions (query only) */
        HANDLE key = nullptr;
        constexpr ACCESS_MASK KEY_QUERY_ONLY = 0x0001; /* KEY_QUERY_VALUE */
        NTSTATUS st = nt_open_key(&key, KEY_QUERY_ONLY, &object_attributes);
        if (!NT_SUCCESS(st) || !key) {
            return false;
        }

        /*
         * We specifically want the "ProductId". Automated malware analysis sandboxes often
         * neglect to randomize this value, thats why we flag it
         */
        UNICODE_STRING value_name;
        rtl_init_unicode_string(&value_name, L"ProductId");

        /* Buffer for KEY_VALUE_PARTIAL_INFORMATION */
        BYTE buffer[128]{};
        ULONG result_length = 0;
        constexpr ULONG key_value_partial_information = 2;

        st = nt_query_value_key(key, &value_name, key_value_partial_information, buffer, sizeof(buffer), &result_length);
        nt_close(key);

        if (!NT_SUCCESS(st)) {
            return false;
        }

        /* Raw structure returned by the native API to manually parse the binary data */
        struct KEY_VALUE_PARTIAL_INFORMATION_LOCAL {
            ULONG TitleIndex;
            ULONG Type;
            ULONG DataLength;
            BYTE Data[1];
        };

        static_assert(offsetof(KEY_VALUE_PARTIAL_INFORMATION_LOCAL, Data) == 12, "Offset of Data member in KEY_VALUE_PARTIAL_INFORMATION_LOCAL must be exactly 12 bytes.");

        if (result_length < offsetof(KEY_VALUE_PARTIAL_INFORMATION_LOCAL, Data) + 1) {
            return false;
        }

        const auto* kv = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION_LOCAL*>(buffer);

        const size_t header_size = offsetof(KEY_VALUE_PARTIAL_INFORMATION_LOCAL, Data);
        if (result_length <= header_size) {
            return false;
        }
        const size_t max_safe_data_len = result_length - header_size;

        const ULONG declared_len = kv->DataLength;
        const size_t actual_data_len = (declared_len < max_safe_data_len) ? declared_len : max_safe_data_len;

        if (actual_data_len == 0) {
            return false;
        }

        char product_id[64] = { 0 };

        const size_t copyLen = (actual_data_len < (sizeof(product_id) - 1)) ? actual_data_len : (sizeof(product_id) - 1);

        std::memcpy(product_id, kv->Data, copyLen);
        product_id[copyLen] = '\0';

        /* A list of known Product IDs associated with public malware analysis sandboxes */
        struct target_pattern {
            const char* product_id;
            enum brand_enum brand;
        };

        constexpr target_pattern targets[] = {
            {"55274-640-2673064-23950", brand_enum::JOEBOX},   
            {"76487-644-3177037-23510", brand_enum::CWSANDBOX}, 
            {"76487-337-8429955-22614", brand_enum::ANUBIS}     
        };

        constexpr size_t target_length = 21;
        if (strlen(product_id) != target_length) {
            return false;
        }

        /*
         * Compare the current system's ProductId against the blacklist
         * if a match is found, we identify the specific sandbox environment and flag it
         */
        for (const auto& target : targets) {
            if (std::memcmp(product_id, target.product_id, target_length) == 0) {
                vma_debug("GAMARUE: Detected ", target.product_id);
                return core::add(target.brand);
            }
        }

        return false;
    }
 

    /**
     * @brief Check for presence of VPC
     * @category Windows, x86_32
     * @implements VM::VPC_INVALID
     */
    [[nodiscard]] static bool vpc_invalid() {
        bool rc = false;
    #if (VMAWARE_X86_32 && !VMAWARE_CLANG)
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        auto is_inside_vpc = [](PEXCEPTION_POINTERS ep) noexcept -> DWORD {
            if (ep && ep->ExceptionRecord && ep->ContextRecord) {
                if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
                    const u8* ip = reinterpret_cast<const u8*>(ep->ExceptionRecord->ExceptionAddress);

                    __try {
                        if (ip && ip[0] == 0x0F && ip[1] == 0x3F && ip[2] == 0x07 && ip[3] == 0x0B) {
                            PCONTEXT ctx = ep->ContextRecord;
                            ctx->Ebx = static_cast<DWORD>(-1); /* Not running VPC */
                            ctx->Eip += 4; /* skip past the 4-byte invalid instruction */
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        return EXCEPTION_CONTINUE_SEARCH;
                    }
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        };

        __try {
            __asm {
                push eax
                push ebx
                push ecx
                push edx

                mov ebx, 0h
                mov eax, 01h

                __emit 0Fh
                __emit 3Fh
                __emit 07h
                __emit 0Bh

                test ebx, ebx
                setz[rc]

                pop edx
                pop ecx
                pop ebx
                pop eax
            }
        }
        __except (is_inside_vpc(GetExceptionInformation())) {
            rc = false;
        }
    #endif

        return rc;
    }


    /**
     * @brief Check str assembly instruction method for VMware
     * @author Alfredo Omella's (S21sec) STR technique, paper describing this technique is located in /papers/
     * @category Windows, x86_32
     * @implements VM::VMWARE_STR
     */
    [[nodiscard]] static bool vmware_str() {
    #if (VMAWARE_X86_32)
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        u16 tr = 0;
        __asm {
            str ax
            mov tr, ax
        }

        if ((tr & 0xFF) == 0x00 && ((tr >> 8) & 0xFF) == 0x40) {
            return core::add(brand_enum::VMWARE);
        }

        return false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for mutex strings of VM brands
     * @category Windows
     * @author from VMDE project
     * @author hfiref0x
     * @implements VM::MUTEX
     */
    [[nodiscard]] static bool mutex() {
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtOpenMutant", "RtlInitUnicodeString", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using rtl_init_unicode_string_fn = void(__stdcall*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        using ntclose_fn = NTSTATUS(__stdcall*)(HANDLE Handle);
        using nt_open_mutant_fn = NTSTATUS(__stdcall*)(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

        const auto nt_open_mutant = reinterpret_cast<nt_open_mutant_fn>(functions[0]);
        const auto rtl_init_unicode_string = reinterpret_cast<rtl_init_unicode_string_fn>(functions[1]);
        const auto nt_close = reinterpret_cast<ntclose_fn>(functions[2]);

        if (!nt_open_mutant || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        auto try_mutex_name = [&](const wchar_t* base_name) noexcept -> bool {
            constexpr wchar_t prefix[] = L"\\BaseNamedObjects\\";
            constexpr size_t prefix_len = (sizeof(prefix) / sizeof(wchar_t)) - 1;
            wchar_t full_path[260];

            /* Memcpy as it is faster than wcscpy/wcscat */
            std::memcpy(full_path, prefix, sizeof(prefix)); 

            const size_t name_len = wcslen(base_name);
            if (prefix_len + name_len < 260) {
                std::memcpy(full_path + prefix_len, base_name, (name_len + 1) * sizeof(wchar_t));
            }
            else {
                /* Should not happen for standard VM artifacts */
                full_path[0] = L'\0';
            }

            const wchar_t* attempts[] = { full_path, base_name };

            for (const wchar_t* path : attempts) {
                if (*path == L'\0') continue;

                UNICODE_STRING u_name;
                rtl_init_unicode_string(&u_name, path);

                OBJECT_ATTRIBUTES obj_attr;
                std::memset(&obj_attr, 0, sizeof(obj_attr));
                obj_attr.Length = sizeof(obj_attr);
                obj_attr.ObjectName = &u_name;
                obj_attr.Attributes = OBJ_CASE_INSENSITIVE;

                HANDLE h_mutant = nullptr;
                const NTSTATUS st = nt_open_mutant(&h_mutant, MUTANT_QUERY_STATE, &obj_attr);

                if (NT_SUCCESS(st)) {
                    if (h_mutant) nt_close(h_mutant);
                    return true;
                }
            }

            return false;
        };

        if (try_mutex_name(L"Sandboxie_SingleInstanceMutex_Control") ||
            try_mutex_name(L"SBIE_BOXED_ServiceInitComplete_Mutex1")) {
            vma_debug("MUTEX: Detected Sandboxie");
            return core::add(brand_enum::SANDBOXIE);
        }

        if (try_mutex_name(L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex")) {
            vma_debug("MUTEX: Detected VPC");
            return core::add(brand_enum::VPC);
        }

        return false;
    }


    /**
     * @brief Check for Cuckoo Sandbox artifacts (directory and communication pipe)
     * @category Windows
     * @author 一半人生, Thomas Roccia (fr0gger)
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @implements VM::CUCKOO
     */
    [[nodiscard]] static bool cuckoo() {
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtOpenFile", "RtlInitUnicodeString", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_openfile_t = 
            NTSTATUS(__stdcall*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
            ULONG ShareAccess, ULONG OpenOptions);
        using rtl_init_unicode_string_t = void(__stdcall*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        using ntclose_t = NTSTATUS(__stdcall*)(HANDLE Handle);

        const auto nt_open_file = reinterpret_cast<nt_openfile_t>(functions[0]);
        const auto rtl_init_unicode_string = reinterpret_cast<rtl_init_unicode_string_t>(functions[1]);
        const auto nt_close = reinterpret_cast<ntclose_t>(functions[2]);

        if (!nt_open_file || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        struct target_artifact {
            const wchar_t* path;
            ACCESS_MASK desired_access;
            ULONG share_access;
            ULONG open_options;
        };

        const target_artifact targets[] = {
            /* Cuckoo Directory */
            {
                L"\\??\\C:\\Cuckoo",
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE
            },
            /* Cuckoo Pipe */
            {
                L"\\??\\pipe\\cuckoo",
                FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                0,
                FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT
            }
        };

        for (const auto& target : targets) {
            UNICODE_STRING path;
            rtl_init_unicode_string(&path, target.path);

            OBJECT_ATTRIBUTES object_attributes;
            ZeroMemory(&object_attributes, sizeof(object_attributes));
            object_attributes.Length = sizeof(object_attributes);
            object_attributes.ObjectName = &path;
            object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

            IO_STATUS_BLOCK iosb;
            HANDLE handle = nullptr;

            const NTSTATUS st = nt_open_file(&handle, target.desired_access, &object_attributes, &iosb, target.share_access, target.open_options);
            if (NT_SUCCESS(st)) {
                if (handle) {
                    nt_close(handle);
                }
                return core::add(brand_enum::CUCKOO);
            }
        }

        return false;
    }


    /**
     * @brief Check for display configurations commonly found in VMs
     * @category Windows
     * @implements VM::DISPLAY
     */
    [[nodiscard]] static bool display() {
        const HDC hdc = GetDC(nullptr);
        const int bpp = GetDeviceCaps(hdc, BITSPIXEL) * GetDeviceCaps(hdc, PLANES);
        const int logpix = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(nullptr, hdc);

        /* Physical monitors are almost always 32bpp and 96–144 DPI */
        if (bpp != 32 || logpix < 90) {
            return true;
        }

        return false;
    }


    /**
     * @brief Check for drivers used in VMs
     * @category Windows
     * @implements VM::DRIVERS
     */
    [[nodiscard]] static bool drivers() {
        struct _SYSTEM_MODULE_INFORMATION {
            PVOID  Reserved[2];
            PVOID  ImageBaseAddress;
            ULONG  ImageSize;
            ULONG  Flags;
            USHORT Index;
            USHORT NameLength;
            USHORT LoadCount;
            USHORT PathLength;
            CHAR   ImageName[256];
        };

        struct _SYSTEM_MODULE_INFORMATION_EX {
            ULONG  NumberOfModules;
            _SYSTEM_MODULE_INFORMATION Module[1];
        };

        using SYSTEM_MODULE_INFORMATION = _SYSTEM_MODULE_INFORMATION;
        using PSYSTEM_MODULE_INFORMATION = _SYSTEM_MODULE_INFORMATION*;
        using SYSTEM_MODULE_INFORMATION_EX = _SYSTEM_MODULE_INFORMATION_EX;
        using PSYSTEM_MODULE_INFORMATION_EX = _SYSTEM_MODULE_INFORMATION_EX*;

        typedef struct _KEY_FULL_INFORMATION {
            LARGE_INTEGER LastWriteTime;
            ULONG         TitleIndex;
            ULONG         ClassOffset;
            ULONG         ClassLength;
            ULONG         SubKeys;
            ULONG         MaxNameLen;
            ULONG         MaxClassLen;
            ULONG         Values;
            ULONG         MaxValueNameLen;
            ULONG         MaxValueDataLen;
            WCHAR         Class[1];
        } KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;

        typedef enum _KEY_INFORMATION_CLASS {
            KeyBasicInformation,
            KeyNodeInformation,
            KeyFullInformation,
            KeyNameInformation,
            KeyCachedInformation,
            KeyFlagsInformation,
            KeyVirtualizationInformation,
            KeyHandleTagsInformation,
            KeyTrustInformation,
            KeyLayerInformation,
            MaxKeyInfoClass
        } KEY_INFORMATION_CLASS;

        constexpr ULONG system_module_information = 11;
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = {
            "NtQuerySystemInformation",
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "RtlInitUnicodeString",
            "NtOpenKey",
            "NtQueryKey",
            "NtClose"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_query_system_information_fn = NTSTATUS(__stdcall*)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG Protect
        );
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

        const auto nt_query_system_information = reinterpret_cast<nt_query_system_information_fn>(functions[0]);
        const auto nt_allocate_virtual_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[1]);
        const auto nt_free_virtual_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[2]);
        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(functions[3]);
        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(functions[4]);
        const auto nt_query_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(functions[5]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[6]);

        if (nt_query_system_information == nullptr || nt_allocate_virtual_memory == nullptr || nt_free_virtual_memory == nullptr ||
            rtl_init_unicode_string == nullptr || nt_open_key == nullptr || nt_query_key == nullptr || nt_close == nullptr) { 
            return false;
        }

        ULONG ul_size = 0;
        NTSTATUS status = nt_query_system_information(system_module_information, nullptr, 0, &ul_size);
        if (status != ((NTSTATUS)0xC0000004L)) {
            return false;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        PVOID allocated_memory = nullptr;
        SIZE_T region_size = ul_size;
        nt_allocate_virtual_memory(current_process, &allocated_memory, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        const auto system_module_info_ex = reinterpret_cast<PSYSTEM_MODULE_INFORMATION_EX>(allocated_memory);
        status = nt_query_system_information(system_module_information, system_module_info_ex, ul_size, &ul_size);
        if (!(((NTSTATUS)(status)) >= 0)) {
            region_size = 0;
            nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
            return false;
        }

        const size_t max_modules = (ul_size - offsetof(_SYSTEM_MODULE_INFORMATION_EX, Module)) / sizeof(_SYSTEM_MODULE_INFORMATION);
        const ULONG number_of_modules = (system_module_info_ex->NumberOfModules < max_modules) ? system_module_info_ex->NumberOfModules : static_cast<ULONG>(max_modules);

        for (ULONG i = 0; i < number_of_modules; ++i) {
            const char* driver_path = reinterpret_cast<const char*>(system_module_info_ex->Module[i].ImageName);
            if (
                strstr(driver_path, "VBoxGuest") || /* Only installed after vbox guest additions */
                strstr(driver_path, "VBoxMouse") ||
                strstr(driver_path, "VBoxSF")
               ) {
                vma_debug("DRIVERS: Detected VBox driver: ", driver_path);
                region_size = 0;
                nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
                return core::add(brand_enum::VBOX);
            }

            if (
                strstr(driver_path, "vmusbmouse") ||
                strstr(driver_path, "vmmemctl")
               ) {
                vma_debug("DRIVERS: Detected VMware driver: ", driver_path);
                region_size = 0;
                nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
                return core::add(brand_enum::VMWARE);
            }
        }

        SIZE_T free_size = 0;
        nt_free_virtual_memory(current_process, &allocated_memory, &free_size, MEM_RELEASE);

        /*
         * Targeted GUIDs:
         * 1. IVSHMEM (Inter-VM Shared Memory). Typically used in KVM/QEMU environments (like Looking Glass) to pass memory between host and guest.
         * 2. Looking Glass Indirect Display Driver (LGIdd).
         */
        constexpr GUID TARGETED_GUIDS[] = {
            { 0xdf576976, 0x569d, 0x4672, { 0x95, 0xa0, 0xf5, 0x7e, 0x4e, 0xa0, 0xb2, 0x10 } },
            { 0x997b0b66, 0xb74c, 0x4017, { 0x9a, 0x89, 0xe4, 0xaa, 0xd4, 0x1d, 0x37, 0x80 } }
        };

        for (const auto& guid : TARGETED_GUIDS) {
            /*
             * Construct the registry path for the DeviceClasses key
             * We access the "DeviceClasses" registry hive directly to find hardware interfaces
             */
            wchar_t interface_class_path[256];
            swprintf_s(
                interface_class_path,
                ARRAYSIZE(interface_class_path),
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2],
                guid.Data4[3], guid.Data4[4], guid.Data4[5],
                guid.Data4[6], guid.Data4[7]
            );

            UNICODE_STRING unicode_path;
            rtl_init_unicode_string(&unicode_path, interface_class_path);

            OBJECT_ATTRIBUTES object_attributes;
            RtlZeroMemory(&object_attributes, sizeof(object_attributes));
            object_attributes.Length = sizeof(object_attributes);
            object_attributes.ObjectName = &unicode_path;
            object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

            HANDLE key = nullptr;
            NTSTATUS st = nt_open_key(&key, KEY_READ, &object_attributes);
            if (!NT_SUCCESS(st) || key == nullptr) {
                continue;
            }

            /*
             * We query the "Full Information" of the key to get the count of subkeys
             * The existence of the class key alone isn't enough cuz Windows might register the class but have no devices
             * If SubKeys > 0, it means actual device instances (for ex. PCI devices) are registered under this interface
             */
            BYTE info_buffer[512] = {};
            ULONG returned_len = 0;
            st = nt_query_key(key, KeyFullInformation, info_buffer, sizeof(info_buffer), &returned_len);

            DWORD number_of_subkeys = 0;
            if (NT_SUCCESS(st) && returned_len >= sizeof(KEY_FULL_INFORMATION)) {
                auto* kfi = reinterpret_cast<KEY_FULL_INFORMATION*>(info_buffer);
                number_of_subkeys = static_cast<DWORD>(kfi->SubKeys);
            }

            nt_close(key);

            if (number_of_subkeys > 0) {
                return core::add(brand_enum::QEMU);
            }
        }

        return false;
    }


    /**
     * @brief Check for virtual GPU capabilities
     * @category Windows
     * @implements VM::GPU_CAPABILITIES
     */
    [[nodiscard]] static bool gpu_capabilities() {
        /*
            Microsoft::WRL::ComPtr<IDirect3D9> d3d9 {
                Direct3DCreate9(D3D_SDK_VERSION)
            };

            if (!d3d9) {
                vma_debug("GPU_CAPABILITIES: Direct3DCreate9 failed");
                return true;
            }

            D3DCAPS9 caps;
            if (FAILED(d3d9->GetDeviceCaps(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, &caps))) {
                vma_debug("GPU_CAPABILITIES: GetDeviceCaps failed");
                return false;
            }

            // if the driver cannot adjust the display gamma ramp dynamically but only in full-screen mode—via the IDirect3DDevice9::SetGammaRamp API
            return !(caps.Caps2 & D3DCAPS2_FULLSCREENGAMMA);
        */

        const HDC hdc = GetDC(nullptr);
        if (!hdc) {
            return true;
        }

        const int color_caps = GetDeviceCaps(hdc, COLORMGMTCAPS);
        ReleaseDC(nullptr, hdc);

        return !(color_caps & CM_GAMMA_RAMP) || color_caps == 0;
    }


    /**
     * @brief Check for vm-specific devices
     * @category Windows
     * @implements VM::HANDLES
     */
    [[nodiscard]] static bool device_handles() {
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "RtlInitUnicodeString", "NtOpenFile", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(functions[0]);
        const auto nt_open_file = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)>(functions[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[2]);

        if (!rtl_init_unicode_string || !nt_open_file || !nt_close) {
            return false;
        }

        auto try_open_mutex = [&](const wchar_t* native_path) noexcept -> HANDLE {
            UNICODE_STRING u_path{};
            u_path.Buffer = const_cast<wchar_t*>(native_path);
            const size_t len_bytes = wcslen(native_path) * sizeof(wchar_t);
            u_path.Length = static_cast<USHORT>(len_bytes);
            u_path.MaximumLength = static_cast<USHORT>(len_bytes + sizeof(wchar_t));

            OBJECT_ATTRIBUTES obj_attr = {
                sizeof(OBJECT_ATTRIBUTES),
                nullptr,
                &u_path,
                OBJ_CASE_INSENSITIVE,
                nullptr,
                nullptr
            };

            IO_STATUS_BLOCK iosb;
            HANDLE h_file = nullptr;

            constexpr ACCESS_MASK desired_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            constexpr ULONG share_access = FILE_SHARE_READ;
            constexpr ULONG open_options = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT;

            const NTSTATUS st = nt_open_file(&h_file, desired_access, &obj_attr, &iosb, share_access, open_options);

            if (NT_SUCCESS(st)) {
                return h_file;
            }
            return INVALID_HANDLE_VALUE;
        };

        constexpr const wchar_t* paths[] = {
            L"\\??\\VBoxMiniRdrDN",    /* \\.\VBoxMiniRdrDN */
            L"\\??\\pipe\\VBoxMiniRdDN",/* \\.\pipe\VBoxMiniRdDN */
            L"\\??\\VBoxTrayIPC",      /* \\.\VBoxTrayIPC */
            L"\\??\\pipe\\VBoxTrayIPC",/* \\.\pipe\VBoxTrayIPC */
            L"\\??\\HGFS",             /* \\.\HGFS (VMware) */
            L"\\??\\pipe\\cuckoo"      /* \\.\pipe\cuckoo (Cuckoo) */
        };

        const size_t path_count = sizeof(paths) / sizeof(paths[0]);
        HANDLE handles[sizeof(paths) / sizeof(paths[0])] = {};

        for (size_t i = 0; i < path_count; ++i) {
            handles[i] = try_open_mutex(paths[i]);
        }

        const bool vbox = (handles[0] != INVALID_HANDLE_VALUE) ||
            (handles[1] != INVALID_HANDLE_VALUE) ||
            (handles[2] != INVALID_HANDLE_VALUE) ||
            (handles[3] != INVALID_HANDLE_VALUE);

        const bool vmware = (handles[4] != INVALID_HANDLE_VALUE);
        const bool cuckoo = (handles[5] != INVALID_HANDLE_VALUE);

        for (size_t i = 0; i < path_count; ++i) {
            if (handles[i] != INVALID_HANDLE_VALUE) {
                (void)nt_close(handles[i]);
                handles[i] = INVALID_HANDLE_VALUE;
            }
        }

        if (vbox) {
            vma_debug("HANDLES: Detected VBox related device handles");
            return core::add(brand_enum::VBOX);
        }

        if (vmware) {
            vma_debug("HANDLES: Detected VMware related device (HGFS)");
            return core::add(brand_enum::VMWARE);
        }

        if (cuckoo) {
            vma_debug("HANDLES: Detected Cuckoo related device (pipe)");
            return core::add(brand_enum::CUCKOO);
        }

        return false;
    }


    /**
     * @brief Check if the number of virtual and logical processors are reported correctly by the system
     * @category Windows, x86
     * @implements VM::VIRTUAL_PROCESSORS
     */
    [[nodiscard]] static bool virtual_processors() {
    #if (VMAWARE_X86)
        int regs[4];
        __cpuid(regs, cpu::leaf::hypervisor);

        const u32 max_leaf = static_cast<u32>(regs[0]);
        if (max_leaf < cpu::leaf::hv_processors) {
            return false;
        }

        __cpuid(regs, cpu::leaf::hv_processors);
        const u32 max_virtual_processors = static_cast<u32>(regs[0]);
        const u32 max_logical_processors = static_cast<u32>(regs[1]);

        vma_debug("VIRTUAL_PROCESSORS: MaxVirtualProcessors -> ", max_virtual_processors, ", MaxLogicalProcessors -> ", max_logical_processors);

        if (max_virtual_processors == 0xFFFFFFFF || max_logical_processors == 0) {
            return true;
        }
    #endif
        return false;
    }

    
    /**
     * @brief Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems
     * @category Windows
     * @link https://evasions.checkpoint.com/src/Evasions/techniques/global-os-objects.html
     * @implements VM::VIRTUAL_REGISTRY
     */
    [[nodiscard]] static bool virtual_registry() {
        struct UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        };
        struct OBJECT_ATTRIBUTES {
            ULONG Length;
            HANDLE RootDirectory;
            UNICODE_STRING* ObjectName;
            ULONG Attributes;
            PVOID SecurityDescriptor;
            PVOID SecurityQualityOfService;
        };
        enum OBJECT_INFORMATION_CLASS {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2
        };
        struct OBJECT_NAME_INFORMATION {
            UNICODE_STRING Name;
        };

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtOpenKey", "NtQueryObject", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));
    
        using POBJECT_NAME_INFORMATION = OBJECT_NAME_INFORMATION*;
        using nt_open_key_fn = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        using nt_query_object_fn = NTSTATUS(__stdcall*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

        const auto nt_open_key = reinterpret_cast<nt_open_key_fn>(functions[0]);
        const auto nt_query_object = reinterpret_cast<nt_query_object_fn>(functions[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[2]);

        if (!nt_open_key || !nt_query_object || !nt_close) {
            return false;
        }

        /* Prepare to open the root USER registry hive */
        UNICODE_STRING key_path{};
        key_path.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        key_path.Length = static_cast<USHORT>(wcslen(key_path.Buffer) * sizeof(WCHAR));
        key_path.MaximumLength = key_path.Length + sizeof(WCHAR);

        OBJECT_ATTRIBUTES object_attributes = {
            sizeof(OBJECT_ATTRIBUTES),
            nullptr,
            &key_path,
            0x00000040L,  /* OBJ_CASE_INSENSITIVE */
            nullptr,
            nullptr
        };

        /*
         * Attempt to open the key. If we are sandboxed, this open call often succeeds,
         * but the underlying handle will point to a virtualized container, not the real OS path
         */
        HANDLE key = nullptr;
        NTSTATUS status = nt_open_key(&key, KEY_READ, reinterpret_cast<POBJECT_ATTRIBUTES>(&object_attributes));
        if (!(((NTSTATUS)(status)) >= 0)) {
            return false;
        }

        /*
         * Ask the kernel: "What is the actual name of the object this handle points to?"
         * Sandboxie implements file system and registry virtualization by redirecting access
         * While the API pretends we opened "\REGISTRY\USER", the handle might actually point to
         * something like "\Device\HarddiskVolume2\Sandbox\User\DefaultBox\RegHive"
         */
        alignas(16) BYTE buffer[1024]{};
        ULONG returned_length = 0;
        status = nt_query_object(key, ObjectNameInformation, buffer, sizeof(buffer), &returned_length);
        nt_close(key);

        if (!(((NTSTATUS)(status)) >= 0)) {
            return false;
        }
        const auto object_name = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);

        UNICODE_STRING expected_name{};
        expected_name.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        expected_name.Length = static_cast<USHORT>(wcslen(expected_name.Buffer) * sizeof(WCHAR));

        /*
         * Compare the requested name vs the actual kernel object name
         * If they don't match, we have been redirected, confirming the presence of Sandboxie
         */
        const bool mismatch = 
            (object_name->Name.Length != expected_name.Length) ||
            (object_name->Name.Buffer == nullptr) ||
            (std::memcmp(object_name->Name.Buffer, expected_name.Buffer, expected_name.Length) != 0);

        return mismatch ? core::add(brand_enum::SANDBOXIE) : false;
    }
    
    
    /**
     * @brief Check if no waveform-audio output devices are present in the system
     * @category Windows
     * @implements VM::AUDIO
     */
    [[nodiscard]] static bool audio() {
        struct KEY_FULL_INFORMATION {
            LARGE_INTEGER LastWriteTime;
            ULONG         TitleIndex;
            ULONG         ClassOffset;
            ULONG         ClassLength;
            ULONG         SubKeys;
            ULONG         MaxNameLen;
            ULONG         MaxClassLen;
            ULONG         Values;
            ULONG         MaxValueNameLen;
            ULONG         MaxValueDataLen;
            WCHAR         Class[1];
        };
        using PKEY_FULL_INFORMATION = KEY_FULL_INFORMATION*;

        enum KEY_INFORMATION_CLASS {
            KeyBasicInformation,
            KeyNodeInformation,
            KeyFullInformation,
            KeyNameInformation,
            KeyCachedInformation,
            KeyFlagsInformation,
            KeyVirtualizationInformation,
            KeyHandleTagsInformation,
            KeyTrustInformation,
            KeyLayerInformation,
            MaxKeyInfoClass
        };

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "RtlInitUnicodeString", "NtOpenKey", "NtQueryKey", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(functions[0]);
        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(functions[1]);
        const auto nt_query_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(functions[2]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[3]);

        if (!rtl_init_unicode_string || !nt_open_key || !nt_query_key || !nt_close) {
            return false;
        }

        /*
         * We are checking for the presence of Audio Render devices
         * Most legitimate user PCs have speakers or headphones (audio endpoints)
         * Automated sandboxes and headless servers often have no audio devices configured
         * We target the MMDevices\Audio\Render key where these endpoints are registered
         */
        const wchar_t* native_path = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render";

        UNICODE_STRING unicode_path;
        rtl_init_unicode_string(&unicode_path, native_path);

        OBJECT_ATTRIBUTES object_attributes;
        RtlZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &unicode_path;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE key = nullptr;

        /*
         * KEY_WOW64_64KEY (0x0100) forces the 32-bit execution environment to access
         * the native 64-bit registry key rather than the redirected Wow6432Node path
         */
        const ACCESS_MASK desired_access = KEY_READ | KEY_WOW64_64KEY;

        NTSTATUS st = nt_open_key(&key, desired_access, &object_attributes);
        if (!NT_SUCCESS(st) || key == nullptr) {
            return false;
        }

        constexpr KEY_INFORMATION_CLASS info_class = KeyFullInformation;
        std::vector<BYTE> info_buffer(512);
        ULONG returned_len = 0;

        /*
         * Query the key information. If the initial query fails, try resizing.
         * If returned_len is unpopulated or invalid, fallback to a safe larger size.
         */
        st = nt_query_key(key, info_class, info_buffer.data(), static_cast<ULONG>(info_buffer.size()), &returned_len);

        if (!NT_SUCCESS(st)) {
            const ULONG target_size = (returned_len > info_buffer.size()) ? returned_len : 2048;
            info_buffer.resize(target_size);
            st = nt_query_key(key, info_class, info_buffer.data(), static_cast<ULONG>(info_buffer.size()), &returned_len);
        }

        bool has_subkeys = true;
        bool query_successful = false;

        if (NT_SUCCESS(st)) {
            constexpr size_t subkeys_offset = offsetof(KEY_FULL_INFORMATION, SubKeys);
            if (info_buffer.size() >= subkeys_offset + sizeof(ULONG)) {
                ULONG subkeys_count = 0;
                std::memcpy(&subkeys_count, info_buffer.data() + subkeys_offset, sizeof(ULONG));
                has_subkeys = (subkeys_count > 0);
                query_successful = true;
            }
        }

        nt_close(key);

        if (!query_successful) {
            return false;
        }

        return !has_subkeys;
    }
    
    
    /**
     * @brief Check for VM-specific ACPI device signatures
     * @category Windows
     * @implements VM::ACPI_SIGNATURE
     */
    [[nodiscard]] static bool acpi_signature() {
        /* Enumerate all devices */
        const HDEVINFO handle_dev_info = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
        if (handle_dev_info == INVALID_HANDLE_VALUE) {
            vma_debug("ACPI_SIGNATURE: SetupDiGetClassDevsW returned false");
            return false;
        }

        SP_DEVINFO_DATA dev_info;
        ZeroMemory(&dev_info, sizeof(dev_info));
        dev_info.cbSize = sizeof(dev_info);
        const DEVPROPKEY key = DEVPKEY_Device_LocationPaths;

        /* Bare metal tokens (case-sensitive to preserve handling against edge-cases) */
        static constexpr const wchar_t* excluded_tokens[] = {
            L"GFX",
            L"IGD", L"IGFX", L"IGPU",
            L"VGA", L"VIDEO", L"DISPLAY", L"GPU",
            L"PCIROOT", L"PNP0A03", L"PNP0A08",
            L"PCH", L"PXS", L"PEG", L"PEGP"
        };

        auto has_excluded_token = [&](const wchar_t* s) noexcept -> bool {
            if (!s || !*s) {
                return false;
            }
            for (const wchar_t* tok : excluded_tokens) {
                if (wcsstr(s, tok) != nullptr) 
                    return true;
            }
            return false;
        };

        for (DWORD idx = 0; SetupDiEnumDeviceInfo(handle_dev_info, idx, &dev_info); ++idx) {
            wchar_t inst_id[MAX_PATH] = { 0 };
            SetupDiGetDeviceInstanceIdW(handle_dev_info, &dev_info, inst_id, MAX_PATH, nullptr);
            if (wcsstr(inst_id, L"PNP0A06") && (wcsstr(inst_id, L"HOTPLUG") || wcsstr(inst_id, L"GPE0") || wcsstr(inst_id, L"SMI"))) {
                vma_debug("ACPI_SIGNATURE: Synthetic QEMU ACPI device detected (PNP0A06)");
                SetupDiDestroyDeviceInfoList(handle_dev_info);
                return core::add(brand_enum::QEMU);
            }

            DEVPROPTYPE prop_type = 0;
            DWORD required_size = 0;

            /* Query required size (bytes) */
            SetupDiGetDevicePropertyW(handle_dev_info, &dev_info, &key, &prop_type, nullptr, 0, &required_size, 0);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size == 0) {
                continue;             
            }

            /* Fetch buffer (multi-sz) */
            std::vector<BYTE> buffer(required_size + (sizeof(wchar_t) * 2), 0);
            if (!SetupDiGetDevicePropertyW(handle_dev_info, &dev_info, &key, &prop_type,
                buffer.data(), required_size, &required_size, 0)) {
                continue;
            }

            const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buffer.data());
            const size_t total_wchars = required_size / sizeof(wchar_t); /* number of wchar_t slots in buffer */
            const wchar_t* buf_end = ptr + (total_wchars ? total_wchars : 0);

            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                VMAWARE_PREFETCH(p + 32, _MM_HINT_T0);

                if (wcsstr(p, L"ACPI(DRAC)")) {
                    vma_debug("ACPI_SIGNATURE: QEMU virtual DRAM Controller (DRAC) ACPI node detected");
                    SetupDiDestroyDeviceInfoList(handle_dev_info);
                    return core::add(brand_enum::QEMU);
                }

                if (wcsstr(inst_id, L"VEN_1022")) {
                    if (wcsstr(p, L"PCI(1F00)") || wcsstr(p, L"PCI(1F02)") || wcsstr(p, L"PCI(1F03)")) {
                        vma_debug("ACPI_SIGNATURE: Impossible AMD Vendor ID mapped to Intel Q35 PCI slot");
                        SetupDiDestroyDeviceInfoList(handle_dev_info);
                        return core::add(brand_enum::QEMU);
                    }
                }

                if (has_excluded_token(p)) {
                    continue;
                }
            }

            static constexpr const wchar_t* vm_signatures[] = {
                L"#ACPI(VMOD)", L"#ACPI(VMBS)", L"#VMBUS(", L"#VPCI("
            };

            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                if (has_excluded_token(p)) {
                    continue;
                }

                for (const wchar_t* sig : vm_signatures) {
                    if (wcsstr(p, sig) != nullptr) {
                        vma_debug("ACPI_SIGNATURE: Detected Hyper-V signatures");
                        SetupDiDestroyDeviceInfoList(handle_dev_info);
                        return core::add(brand_enum::HYPERV);
                    }
                }
            }
        }

        SetupDiDestroyDeviceInfoList(handle_dev_info);
        return false;
    }


    /**
     * @brief Check if after raising two traps at the same RIP, a hypervisor interferes with the instruction pointer delivery
     * @category Windows, x86_64
     * @implements VM::TRAP
     */
    [[nodiscard]] static bool trap() {
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        bool hypervisor_caught = false;
    #if (VMAWARE_X86_64)
        /*
         * When a single-step (TF) and hardware breakpoint (DR0) collide, Intel CPUs set both DR6.BS and DR6.B0.
         * AMD CPUs prioritize the breakpoint, setting only its corresponding bit in DR6.
         */
        if (!cpu::is_intel()) {
            return false;
        }

        /* Mobile SKUs can "false flag" this check */
        const char* brand = cpu::get_brand();
        for (const char* c = brand; *c; ++c) {
            if (*c == 'U') {
                if (c > brand && (c[-1] >= '0' && c[-1] <= '9')) {
                    if (c[1] == ' ' || c[1] == '\0') {
                        return false;
                    }
                }
            }
        }

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = {
            "NtGetContextThread",
            "NtSetContextThread"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_get_context_thread_fn = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using nt_set_context_thread_fn = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);

        nt_get_context_thread_fn volatile nt_get_context_thread = reinterpret_cast<nt_get_context_thread_fn>(functions[0]);
        nt_set_context_thread_fn volatile nt_set_context_thread = reinterpret_cast<nt_set_context_thread_fn>(functions[1]);

        if (!nt_get_context_thread || !nt_set_context_thread) {
            return false;
        }

        u8 hit_count = 0;
        CONTEXT original_context{};
        original_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);

        if (!NT_SUCCESS(nt_get_context_thread(current_thread, &original_context))) {
            return false;
        }

        /*
         * Set DR0 to trampoline_stub + 14 (Instruction: mov rbx, r8)
         * Offset: mov_r8_rbx(3) + pushfq(1) + or(7) + popfq(1) + cpuid(2) = 14
         */
        const uintptr_t expected_trap_address = reinterpret_cast<uintptr_t>(trampoline_stub) + 14;

        CONTEXT debug_context = original_context;
        debug_context.Dr0 = expected_trap_address; /* Single-step breakpoint address */
        debug_context.Dr7 = 1;                     /* Enable Local Breakpoint 0 */

        if (!NT_SUCCESS(nt_set_context_thread(current_thread, &debug_context))) {
            nt_set_context_thread(current_thread, &original_context);
            return false;
        }

        /* Context structure to pass data to the static SEH handler */
        struct trap_context {
            uintptr_t expectedTrapAddr;
            u8* hitCount;
            bool* hypervisor_caught;
        };

        /* Static struct for SEH filtering to avoid release-mode lambda optimizations */
        struct exception_handler {
            static VMAWARE_NOINLINE LONG execute(const u32 code, EXCEPTION_POINTERS* info, trap_context* ctx) noexcept {
                if (!info || !info->ExceptionRecord || !info->ContextRecord) {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                if (code != static_cast<DWORD>(0x80000004L)) {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                /* Verify exception occurred at our calculated instruction offset */
                if (reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress) != ctx->expectedTrapAddr) {
                    info->ContextRecord->EFlags &= ~0x100; /* Clear TF */
                    info->ContextRecord->Dr7 &= ~1;        /* Clear DR0 Enable */
                    *ctx->hypervisor_caught = true;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                (*ctx->hitCount)++;

                /* Check if both Trap Flag and DR0 contributed to the exception status */
                constexpr u64 required_bits = (1ULL << 14) | 1ULL; /* BS | B0 */
                const u64 status = info->ContextRecord->Dr6;

                if ((status & required_bits) != required_bits) {
                    if (util::hyper_x() != HYPERV_HOST) {
                        *ctx->hypervisor_caught = true;
                    }
                }

                /* Clear Trap Flag to stop single-stepping */
                info->ContextRecord->EFlags &= ~0x100;

                /* Clear DR7 Local Enable 0 to disable the hardware breakpoint */
                info->ContextRecord->Dr7 &= ~1;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        };

        trap_context ctx = { expected_trap_address, &hit_count, &hypervisor_caught };
        VMAWARE_UNUSED(ctx);

        __try {
            memory::execute(trampoline_stub);
        }
        __except (exception_handler::execute(GetExceptionCode(), reinterpret_cast<EXCEPTION_POINTERS*>(_exception_info()), &ctx)) {
            /* Unreachable, the exception_handler always returns CONTINUE_EXECUTION or CONTINUE_SEARCH */
        }

        /* If the hypervisor swallowed the trap event entirely, the hitcount will be 0 */
        if (hit_count != 1) {
            hypervisor_caught = true;
        }

        nt_set_context_thread(current_thread, &original_context);
    #endif
        return hypervisor_caught;
    }


    /**
     * @brief Check if after executing an undefined instruction, a hypervisor misinterpret it as a system call
     * @category Windows
     * @implements VM::UD
     */
    [[nodiscard]] static bool ud() {
    #if (VMAWARE_X86) || (VMAWARE_ARM32) || (VMAWARE_ARM64)
        bool saw_ud = false;

        __try {
            memory::execute(ud_stub);
        }
        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            saw_ud = true;
        }

        return !saw_ud;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check if a hypervisor does not properly restore the interruptibility state after a VM-exit
     * @category Windows
     * @implements VM::INTERRUPT_SHADOW
     */
    [[nodiscard]] static bool interrupt_shadow() {
    #if (VMAWARE_X86)
        if (util::hyper_x() == HYPERV_HOST) {
            return false;
        }
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        struct exception_handler {
            static VMAWARE_NOINLINE int execute(const unsigned int code, struct _EXCEPTION_POINTERS* ep, volatile ULONG_PTR* out_trap_ip, volatile bool* out_anomaly) {
                if (code == EXCEPTION_SINGLE_STEP && ep && ep->ContextRecord) {
                #if (VMAWARE_X86_64)
                    *out_trap_ip = ep->ContextRecord->Rip;
                #else
                    * out_trap_ip = ep->ContextRecord->Eip;
                #endif
                    ep->ContextRecord->EFlags &= ~0x100; /* clear TF to resume execution */
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                vma_debug("INTERRUPT_SHADOW: Exception anomaly detected, hypervisor seems to be present with CPUID interception disabled");
                *out_anomaly = true;
                return EXCEPTION_EXECUTE_HANDLER;
            }
        };

        volatile ULONG_PTR trap_ip = 0;
        volatile bool anomaly_detected = false;
        bool rdpru_available = false;

        if (cpu::is_amd()) {
            u32 a = 0, b = 0, c = 0, d = 0;
            cpu::cpuid(a, b, c, d, cpu::leaf::ext_limits);
            rdpru_available = ((b & (1 << 4)) != 0);
        }
    #endif

    #if (VMAWARE_X86_32) && !(VMAWARE_CLANG || VMAWARE_GCC)
        bool hypervisor_detected = false;
        ULONG_PTR baremetal_target_ip = 0;

        trap_ip = 0;
        anomaly_detected = false;
        __try {
            __asm {
                mov dword ptr[baremetal_target_ip], offset baremetal_target
                push ebx
                xor eax, eax
                mov ax, ss
                pushfd
                or dword ptr[esp], 0x100 /* set TF */
                popfd
                mov ss, ax
                cpuid
                baremetal_target :
                pop ebx
                    nop
                    pushfd
                    and dword ptr[esp], 0xFFFFFEFF
                    popfd
            }
        }
        __except (exception_handler::execute(GetExceptionCode(), GetExceptionInformation(), &trap_ip, &anomaly_detected)) {}

        if (anomaly_detected || trap_ip == 0 || trap_ip != baremetal_target_ip) {
            hypervisor_detected = true;
        }

        if (rdpru_available) {
            trap_ip = 0;
            anomaly_detected = false;
            __try {
                __asm {
                    mov dword ptr[baremetal_target_ip], offset baremetal_target_rdpru
                    push ebx
                    xor ecx, ecx
                    xor eax, eax
                    mov ax, ss
                    pushfd
                    or dword ptr[esp], 0x100 /* set TF */
                    popfd
                    mov ss, ax
                    _emit 0x0F
                    _emit 0x01
                    _emit 0xFD
                    baremetal_target_rdpru :
                    pop ebx
                        nop
                        pushfd
                        and dword ptr[esp], 0xFFFFFEFF
                        popfd
                }
            }
            __except (exception_handler::execute(GetExceptionCode(), GetExceptionInformation(), &trap_ip, &anomaly_detected)) {}

            if (anomaly_detected || trap_ip == 0 || trap_ip != baremetal_target_ip) {
                hypervisor_detected = true;
            }
        }

        return hypervisor_detected;

    #elif (VMAWARE_X86_64) || ((VMAWARE_X86_32) && (VMAWARE_CLANG || VMAWARE_GCC))
        bool hypervisor_detected = false;
        ULONG_PTR baremetal_target_ip = 0;

        trap_ip = 0;
        anomaly_detected = false;
        baremetal_target_ip = reinterpret_cast<ULONG_PTR>(cpuid_blockstep_stub) + 18;
        __try {
            memory::execute(cpuid_blockstep_stub);
        }
        __except (exception_handler::execute(GetExceptionCode(), GetExceptionInformation(), &trap_ip, &anomaly_detected)) {}

        if (anomaly_detected || trap_ip == 0 || trap_ip != baremetal_target_ip) {
            hypervisor_detected = true;
        }

        if (rdpru_available) {
            trap_ip = 0;
            anomaly_detected = false;
            baremetal_target_ip = reinterpret_cast<ULONG_PTR>(rdpru_blockstep_stub) + 21;
            __try {
                memory::execute(rdpru_blockstep_stub);
            }
            __except (exception_handler::execute(GetExceptionCode(), GetExceptionInformation(), &trap_ip, &anomaly_detected)) {}

            if (anomaly_detected || trap_ip == 0 || trap_ip != baremetal_target_ip) {
                hypervisor_detected = true;
            }
        }

        return hypervisor_detected;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check if Dark Byte's VM is present
     * @category Windows
     * @implements VM::DBVM
     */
    [[nodiscard]] static bool dbvm() {
    #if (!VMAWARE_X86_64)
        return false;
    #else
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        constexpr u32 PW2 = 0xFEDCBA98U;

        struct vmcall_info {
            u32 structsize;
            u32 level2pass;
            u32 command;
        };

        vmcall_info vmcall_info = {};
        u64 vmcall_result = 0;

        const bool is_amd = cpu::is_amd();

        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtGetContextThread", "NtSetContextThread" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        const auto nt_get_context_thread = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PCONTEXT)>(functions[0]);
        const auto nt_set_context_thread = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PCONTEXT)>(functions[1]);

        if (!nt_get_context_thread || !nt_set_context_thread) {
            return false;
        }

        auto try_keys = [&]() noexcept -> bool {
            /* Store forwarding */
            vmcall_info.structsize = static_cast<u32>(sizeof(vmcall_info));
            vmcall_info.level2pass = PW2;
            vmcall_info.command = 0;
            vmcall_result = 0;

            const void* target_stub = is_amd ? dbvm_amd_stub : dbvm_intel_stub;

            __try {
                memory::execute(target_stub, &vmcall_info, &vmcall_result);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { /* EXCEPTION_ILLEGAL_INSTRUCTION normally, EXCEPTION_ACCESS_VIOLATION_READ on edge-cases */
                vmcall_result = 0;
            }

            return (((vmcall_result >> 24) & 0xFF) == 0xCE); /* the VM returns status in bits 24–31; Cheat Engine uses 0xCE here */
        };

        /*
         * Pure ICEBP RIP Advancement Check (Clean DR State)
         * Verifies if the hypervisor correctly increments guest RIP when emulating ICEBP
         */
        auto try_icebp = [&]() noexcept -> bool {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!NT_SUCCESS(nt_get_context_thread(current_thread, &ctx))) {
                return false;
            }

            /* Save old debug register configuration */
            const auto old_dr0 = ctx.Dr0;
            const auto old_dr1 = ctx.Dr1;
            const auto old_dr2 = ctx.Dr2;
            const auto old_dr3 = ctx.Dr3;
            const auto old_dr6 = ctx.Dr6;
            const auto old_dr7 = ctx.Dr7;

            /* Clean all debug registers to ensure we test pure trap-class behavior */
            ctx.Dr0 = 0;
            ctx.Dr1 = 0;
            ctx.Dr2 = 0;
            ctx.Dr3 = 0;
            ctx.Dr6 = 0;
            ctx.Dr7 = 0;

            if (!NT_SUCCESS(nt_set_context_thread(current_thread, &ctx))) {
                return false;
            }

            bool rip_failed = false;
            bool step_triggered = false;
            const u64 stub_base = reinterpret_cast<u64>(dbvm_icebp_stub);

            struct exception_handler {
                static VMAWARE_NOINLINE LONG execute(
                    const EXCEPTION_POINTERS* ep,
                    DWORD exception_code,
                    bool* rip_failed,
                    bool* step_triggered,
                    u64 stub_base_addr
                ) {
                    if (exception_code == EXCEPTION_SINGLE_STEP && ep && ep->ContextRecord) {
                        *step_triggered = true;
                        const u64 exception_rip = ep->ContextRecord->Rip;

                        /*
                         * Under DBVM, the exception context contains a RIP pointing directly
                         * to the ICEBP instruction (stub_base_addr) instead of (stub_base_addr + 1)
                         */
                        if (exception_rip == stub_base_addr) {
                            *rip_failed = true;
                            /* Manually advance RIP past ICEBP (0xF1) to RET (0xC3) to avoid an infinite loop */
                            ep->ContextRecord->Rip = stub_base_addr + 1;
                        }
                    }
                    return EXCEPTION_EXECUTE_HANDLER;
                }
            };

            __try {
                memory::execute(dbvm_icebp_stub);
            }
            __except (exception_handler::execute(
                GetExceptionInformation(),
                GetExceptionCode(),
                &rip_failed,
                &step_triggered,
                stub_base
            )) {
                /* Handled */
            }

            /* Restore original debug registers */
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx.Dr0 = old_dr0;
            ctx.Dr1 = old_dr1;
            ctx.Dr2 = old_dr2;
            ctx.Dr3 = old_dr3;
            ctx.Dr6 = old_dr6;
            ctx.Dr7 = old_dr7;
            nt_set_context_thread(current_thread, &ctx);

            if (!step_triggered) {
                vma_debug("DBVM: ICEBP exception didn't trigger #DB");
                return true; /* Hypervisor swallowed the trap entirely, but should not happen */
            }

            if (rip_failed) {
                vma_debug("DBVM: ICEBP failed to advance guest RIP");
                return true;
            }

            return false;
        };

        const bool found_keys = try_keys();
        const bool found_icebp = try_icebp();

        if (found_keys) {
            return core::add(brand_enum::DBVM);
        }

        return found_icebp;
    #endif
    }

    /**
     * @brief Check for any signs of VMs in Windows kernel object entities 
     * @category Windows
     * @implements VM::KERNEL_OBJECTS
     */
    [[nodiscard]] static bool kernel_objects() {
        struct OBJECT_DIRECTORY_INFORMATION {
            UNICODE_STRING Name;
            UNICODE_STRING TypeName;
        };

        using POBJECT_DIRECTORY_INFORMATION = OBJECT_DIRECTORY_INFORMATION*;
        constexpr auto DIRECTORY_QUERY = 0x0001;
        constexpr NTSTATUS NO_MORE_ENTRIES = 0x8000001A;

        HANDLE dir = nullptr;
        OBJECT_ATTRIBUTES object_attributes{};
        UNICODE_STRING dir_name{};
        NTSTATUS status;

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtOpenDirectoryObject", "NtQueryDirectoryObject", "NtClose" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        const auto nt_open_directory_object = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(functions[0]);
        const auto nt_query_directory_object = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)>(functions[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(functions[2]);

        if (!nt_open_directory_object || !nt_query_directory_object || !nt_close) {
            return false;
        }

        /*
         * Prepare to open the root "\Device" directory in the Object Manager namespace
         * This is different from the file system and we are looking for kernel objects created by drivers
         */
        constexpr const wchar_t* device_dir_path = L"\\Device";
        dir_name.Buffer = (PWSTR)device_dir_path;
        dir_name.Length = (USHORT)(wcslen(device_dir_path) * sizeof(wchar_t));
        dir_name.MaximumLength = dir_name.Length + sizeof(wchar_t);

        InitializeObjectAttributes(&object_attributes, &dir_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        /* Open the directory object so we can enumerate its contents */
        status = nt_open_directory_object(&dir, DIRECTORY_QUERY, &object_attributes);

        if (!NT_SUCCESS(status)) {
            return false;
        }

        /*
         * Set up a buffer for querying directory entries
         * We process entries one by one using a context index
         */
        std::vector<BYTE> buffer(4096);
        constexpr size_t MAX_DIR_BUFFER = 64 * 1024;
        ULONG context = 0;
        ULONG returned_length = 0;

        while (true) {
            /*
             * Query the next single object in the directory
             * 'ReturnSingleEntry' is TRUE to simplify buffer parsing logic
             */
            status = nt_query_directory_object(
                dir,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                TRUE,
                FALSE,
                &context,
                &returned_length
            );

            /* Stop if we have iterated through all objects */
            if (status == NO_MORE_ENTRIES) {
                break;
            }

            /*
             * Handle buffer sizing. If the buffer is too small, the kernel tells us how much it needs
             * We resize and retry, but impose a sanity cap to prevent memory issues
             */
            if (!NT_SUCCESS(status)) {
                if (returned_length > buffer.size()) {
                    size_t new_size = static_cast<size_t>(returned_length);
                    if (new_size > MAX_DIR_BUFFER) new_size = MAX_DIR_BUFFER;
                    if (new_size <= buffer.size()) {
                        nt_close(dir);
                        return false;
                    }
                    try {
                        buffer.resize(new_size);
                    }
                    catch (...) {
                        nt_close(dir);
                        return false;
                    }
                    continue;
                }
                nt_close(dir);
                return false;
            }

            /* Validate the returned data length to ensure we don't read out of bounds */
            const size_t used_len = (returned_length == 0) ? buffer.size() : static_cast<size_t>(returned_length);
            if (used_len < sizeof(OBJECT_DIRECTORY_INFORMATION) || used_len > buffer.size()) {
                nt_close(dir);
                return false;
            }

            const POBJECT_DIRECTORY_INFORMATION object_directory_information = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer.data());

            /* Memory boundaries just for safe pointer arithmetic */
            const uintptr_t buf_base = reinterpret_cast<uintptr_t>(buffer.data());
            const uintptr_t buf_end = buf_base + used_len;

            std::wstring object_name;
            bool found_name = false;

            /*
             * Extract the name using the explicit Name pointer in the structure
             * We strictly validate that the pointer falls within our allocated buffer to prevent crashes
             */
            const size_t nameBytes = static_cast<size_t>(object_directory_information->Name.Length);
            const uintptr_t name_ptr = reinterpret_cast<uintptr_t>(object_directory_information->Name.Buffer);

            if (nameBytes > 0 && (nameBytes % sizeof(wchar_t) == 0)) {
                const uintptr_t min_valid_ptr = buf_base + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (name_ptr >= min_valid_ptr && (name_ptr + nameBytes) <= buf_end && (name_ptr % sizeof(wchar_t) == 0)) {
                    const wchar_t* wname = reinterpret_cast<const wchar_t*>(name_ptr);
                    const size_t wlen = nameBytes / sizeof(wchar_t);
                    bool found_term = false;
                    /* Scan for null terminator just in case */
                    for (size_t i = 0; i < wlen; ++i) {
                        if (wname[i] == L'\0') { 
                            object_name.assign(wname, i); 
                            found_term = true;
                            break; 
                        }
                    }
                    if (!found_term) {
                        object_name.assign(wname, wlen);
                    }
                    found_name = true;
                }
            }

            /* If the explicit pointer was invalid, assume the string data immediately follows the structure */
            if (!found_name) {
                const uintptr_t altStart = buf_base + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (altStart >= buf_end) {
                    nt_close(dir);
                    return false;
                }
                const size_t maxBytes = buf_end - altStart;
                if (maxBytes < sizeof(wchar_t)) {
                    nt_close(dir);
                    return false;
                }
                const wchar_t* alt_ptr = reinterpret_cast<const wchar_t*>(buffer.data() + (altStart - buf_base));
                const size_t max_chars = maxBytes / sizeof(wchar_t);

                size_t realChars = 0;
                for (; realChars < max_chars; ++realChars) {
                    if (alt_ptr[realChars] == L'\0') {
                        break;
                    }
                }
                if (realChars == max_chars) {
                    nt_close(dir);
                    return false;
                }
                object_name.assign(alt_ptr, realChars);
                found_name = true;
            }

            if (!found_name) {
                nt_close(dir);
                return false;
            }

            /* "VmGenerationCounter" and "VmGid" are created by the Hyper-V VM Bus provider */
            if (object_name == L"VmGenerationCounter") {
                nt_close(dir);
                vma_debug("KERNEL_OBJECTS: Detected VmGenerationCounter");
                return core::add(brand_enum::HYPERV);
            }
            if (object_name == L"VmGid") {
                nt_close(dir);
                vma_debug("KERNEL_OBJECTS: Detected VmGid");
                return core::add(brand_enum::HYPERV);
            }
        }

        nt_close(dir);
        return false;
    }


    /**
     * @brief Check for known NVRAM signatures that are present on virtual firmware
     * @category Windows
     * @warning Permissions required
     * @implements VM::NVRAM
     */
    static bool nvram() {
        if (!util::is_admin()) {
            return false;
        }

        struct VARIABLE_NAME { ULONG NextEntryOffset; GUID VendorGuid; WCHAR Name[1]; };
        using variable_name_ptr = VARIABLE_NAME*;
        bool detection_result = false;

        /* Handles and buffers */
        HANDLE token_handle = nullptr;
        PVOID enum_base_buffer = nullptr;
        BYTE* pk_default_buf = nullptr;
        bool privilege_state_saved = false;
        TOKEN_PRIVILEGES previous_privileges{};
        DWORD previous_privileges_size = sizeof(previous_privileges);
        LUID luid_struct{};

        using nt_enumerate_system_environment_values_ex_fn = NTSTATUS(__stdcall*)(ULONG, PVOID, PULONG);
        using nt_query_system_environment_value_ex_fn = NTSTATUS(__stdcall*)(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes);
        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);

        /* Function pointers */
        nt_enumerate_system_environment_values_ex_fn nt_enumerate_values = nullptr;
        nt_allocate_virtual_memory_fn nt_allocate_memory = nullptr;
        nt_free_virtual_memory_fn nt_free_memory = nullptr;
        nt_query_system_environment_value_ex_fn nt_query_value = nullptr;

        const HANDLE current_process_handle = reinterpret_cast<HANDLE>(-1LL);

        /*
         * -------------------------------------------------------------------------
         * helper lambdas
         * -------------------------------------------------------------------------
         */
        auto buffer_contains_ascii_ci = [](const BYTE* data, size_t len, const char* pat) noexcept -> bool {
            if (!data || len == 0 || !pat) {
                return false;
            }

            const size_t plen = strlen(pat); 
            if (len < plen) {
                return false;
            }

            const BYTE p0 = static_cast<BYTE>((pat[0] >= 'A' && pat[0] <= 'Z') ? (pat[0] + 32) : pat[0]);
            const BYTE* end = data + (len - plen);
            for (const BYTE* p = data; p <= end; ++p) {
                BYTE c0 = *p;
                c0 = static_cast<BYTE>((c0 >= 'A' && c0 <= 'Z') ? (c0 + 32) : c0);
                if (c0 != p0) {
                    continue;
                }

                bool ok = true;
                for (size_t j = 1; j < plen; ++j) {
                    BYTE dj = p[j];
                    dj = static_cast<BYTE>((dj >= 'A' && dj <= 'Z') ? (dj + 32) : dj);
                    BYTE pj = static_cast<BYTE>((pat[j] >= 'A' && pat[j] <= 'Z') ? (pat[j] + 32) : pat[j]);
                    if (dj != pj) {
                        ok = false;
                        break;
                    }
                }

                if (ok) {
                    return true;
                }
            }

            return false;
        };

        auto buffer_contains_utf16le_ci = [](const WCHAR* data, size_t wlen, const wchar_t* pat) noexcept -> bool {
            if (!data || wlen == 0 || !pat) {
                return false;
            }

            const size_t plen = wcslen(pat); 
            if (wlen < plen) {
                return false;
            }

            const WCHAR p0 = static_cast<WCHAR>((pat[0] >= L'A' && pat[0] <= L'Z') ? (pat[0] + 32) : pat[0]);
            const WCHAR* end = data + (wlen - plen);
            for (const WCHAR* p = data; p <= end; ++p) {
                WCHAR c0 = *p; 
                c0 = static_cast<WCHAR>((c0 >= L'A' && c0 <= L'Z') ? (c0 + 32) : c0);
                if (c0 != p0) {
                    continue;
                }

                bool ok = true;
                for (size_t j = 1; j < plen; ++j) {
                    WCHAR dj = p[j]; 
                    dj = static_cast<WCHAR>((dj >= L'A' && dj <= L'Z') ? (dj + 32) : dj);
                    WCHAR pj = static_cast<WCHAR>((pat[j] >= L'A' && pat[j] <= L'Z') ? (pat[j] + 32) : pat[j]);
                    if (dj != pj) { 
                        ok = false; 
                        break;  
                    }
                }
                if (ok) {
                    return true;
                }
            }

            return false;
        };

        auto read_variable_to_buffer = [&](const std::wstring& name, GUID& guid, BYTE*& out_buf, SIZE_T& out_len) noexcept -> bool {
            UNICODE_STRING uni_str{};
            uni_str.Buffer = const_cast<PWSTR>(name.c_str());
            uni_str.Length = static_cast<USHORT>(name.length() * sizeof(wchar_t));
            uni_str.MaximumLength = uni_str.Length + sizeof(wchar_t);

            ULONG required_size = 0;
            (void)nt_query_value(&uni_str, &guid, nullptr, &required_size, nullptr);
            if (required_size == 0) {
                return false;
            }

            PVOID allocation_base = nullptr;
            SIZE_T alloc_size = required_size;
            if (alloc_size < 0x1000) {
                alloc_size = 0x1000;
            }

            NTSTATUS status = nt_allocate_memory(current_process_handle, &allocation_base, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0 || !allocation_base) {
                out_buf = nullptr;
                out_len = 0;
                return false;
            }

            status = nt_query_value(&uni_str, &guid, allocation_base, &required_size, nullptr);
            if (status == 0) {
                out_buf = reinterpret_cast<BYTE*>(allocation_base);
                out_len = required_size;
                return true;
            }

            SIZE_T zero_s = 0;
            nt_free_memory(current_process_handle, &allocation_base, &zero_s, 0x8000);
            out_buf = nullptr;
            out_len = 0;
            return false;
        };

        auto cleanup = [&](auto& ptr) noexcept {
            if (ptr) {
                PVOID base = ptr;
                SIZE_T size = 0;
                nt_free_memory(current_process_handle, &base, &size, 0x8000);
                ptr = nullptr;
            }
        };

        /*
         * -------------------------------------------------------------------------
         * main logic block
         * -------------------------------------------------------------------------
         */
        do {
            if (!OpenProcessToken(current_process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
                break;
            }
            if (!LookupPrivilegeValue(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid_struct)) {
                break;
            }

            TOKEN_PRIVILEGES tp_enable{};
            tp_enable.PrivilegeCount = 1;
            tp_enable.Privileges[0].Luid = luid_struct;
            tp_enable.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            previous_privileges_size = sizeof(previous_privileges);
            if (!AdjustTokenPrivileges(token_handle, FALSE, &tp_enable, previous_privileges_size, &previous_privileges, &previous_privileges_size)) {            
                break;
            }
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
                break;
            }
            privilege_state_saved = true;

            const HMODULE ntdll = memory::get_module(true);
            if (!ntdll) {
                break;
            }

            constexpr const char* function_names[] = { "NtEnumerateSystemEnvironmentValuesEx", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtQuerySystemEnvironmentValueEx" };
            void* functions[ARRAYSIZE(function_names)] = {};
            memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

            nt_enumerate_values = reinterpret_cast<nt_enumerate_system_environment_values_ex_fn>(functions[0]);
            nt_allocate_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[1]);
            nt_free_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[2]);
            nt_query_value = reinterpret_cast<nt_query_system_environment_value_ex_fn>(functions[3]);

            if (!nt_enumerate_values || !nt_allocate_memory || !nt_free_memory || !nt_query_value) {
                break;
            }

            NTSTATUS alloc_status = 0;
            ULONG buffer_required_length = 0;

            /* Ask for size */
            nt_enumerate_values(static_cast<ULONG>(1), nullptr, &buffer_required_length);

            if (buffer_required_length != 0) {
                SIZE_T enum_alloc_size = 0;
                enum_alloc_size = static_cast<SIZE_T>(buffer_required_length);
                alloc_status = nt_allocate_memory(current_process_handle, &enum_base_buffer, 0, &enum_alloc_size, static_cast<ULONG>(MEM_COMMIT | MEM_RESERVE), static_cast<ULONG>(PAGE_READWRITE));

                if (alloc_status == 0 && enum_base_buffer) {
                    alloc_status = nt_enumerate_values(static_cast<ULONG>(1), enum_base_buffer, &buffer_required_length);
                    if (alloc_status != 0) {
                        SIZE_T zero_size = 0;
                        nt_free_memory(current_process_handle, &enum_base_buffer, &zero_size, 0x8000);
                        enum_base_buffer = nullptr;
                    }
                }
            }          

            if (alloc_status != 0 || !enum_base_buffer || buffer_required_length == 0) {
                vma_debug("NVRAM: System is not UEFI");
                break;
            }

            /*
             * ---------------------------------------------------------------------
             * constants and data
             * ---------------------------------------------------------------------
             */
            constexpr const char redhat_sig_ascii[] = "red hat";
            constexpr const wchar_t redhat_sig_wide[] = L"red hat";
            SIZE_T pk_default_len = 0;
            variable_name_ptr current_var = reinterpret_cast<variable_name_ptr>(enum_base_buffer);
            const size_t buffer_total_size = static_cast<size_t>(buffer_required_length);
            constexpr size_t MAX_NAME_BYTE_LIMIT = 4096;
            bool should_break_loop = false;

            /*
             * ---------------------------------------------------------------------
             * iteration loop
             * ---------------------------------------------------------------------
             */
            while (true) {
                const uintptr_t base_address = reinterpret_cast<uintptr_t>(enum_base_buffer);
                const uintptr_t current_address = reinterpret_cast<uintptr_t>(current_var);

                if (current_address < base_address) {
                    break;
                }

                const size_t current_offset = static_cast<size_t>(current_address - base_address);
                if (current_offset >= buffer_total_size) {
                    break;
                }

                const size_t name_struct_offset = offsetof(VARIABLE_NAME, Name);
                if (buffer_total_size - current_offset < name_struct_offset) {
                    break;
                }

                size_t name_max_bytes = 0;
                if (current_var->NextEntryOffset != 0) {
                    const SIZE_T next_entry = static_cast<SIZE_T>(current_var->NextEntryOffset);
                    if (next_entry <= name_struct_offset) { 
                        should_break_loop = true; 
                        break;
                    }
                    if (next_entry > buffer_total_size - current_offset) {
                        break;
                    }

                    name_max_bytes = next_entry - name_struct_offset;
                }
                else {
                    if (current_offset + name_struct_offset >= buffer_total_size) {
                        should_break_loop = true;
                        break; 
                    }

                    name_max_bytes = buffer_total_size - (current_offset + name_struct_offset);
                }

                if (name_max_bytes > MAX_NAME_BYTE_LIMIT) {
                    name_max_bytes = MAX_NAME_BYTE_LIMIT;
                }

                std::wstring var_name_view;
                if (name_max_bytes >= sizeof(WCHAR)) {
                    const WCHAR* name_ptr = reinterpret_cast<const WCHAR*>(reinterpret_cast<const BYTE*>(current_var) + name_struct_offset);
                    const size_t max_chars = name_max_bytes / sizeof(WCHAR);
                    size_t real_chars = 0;
                    while (real_chars < max_chars && name_ptr[real_chars] != L'\0') {             
                        ++real_chars;
                    }

                    if (real_chars == max_chars) { 
                        should_break_loop = true;
                        break; 
                    }

                    var_name_view = std::wstring(name_ptr, real_chars);
                }

                /* Presence checks */
                if (!var_name_view.empty() && var_name_view.rfind(L"VMM", 0) == 0) {
                    vma_debug("NVRAM: Detected hypervisor signature");
                    should_break_loop = true;
                    break;
                }

                /* Read variables */
                if (var_name_view == L"PKDefault" && pk_default_buf == nullptr) {
                    (void)read_variable_to_buffer(std::wstring(var_name_view), current_var->VendorGuid, pk_default_buf, pk_default_len);
                }

                if (current_var->NextEntryOffset == 0) {
                    break;
                }

                const SIZE_T next_entry_off = static_cast<SIZE_T>(current_var->NextEntryOffset);
                const size_t next_var_offset = current_offset + next_entry_off;
                if (next_var_offset <= current_offset || next_var_offset > buffer_total_size) {
                    break;
                }

                current_var = reinterpret_cast<variable_name_ptr>(reinterpret_cast<PBYTE>(enum_base_buffer) + next_var_offset);
            }

            if (should_break_loop) {
                break;
            }

            /* Free enumeration buffer */
            SIZE_T z = 0;
            nt_free_memory(current_process_handle, &enum_base_buffer, &z, 0x8000);
            enum_base_buffer = nullptr;          

            /* Check for official red hat certs (QEMU/OVMF) */
            bool found_redhat = false;
            if (pk_default_buf && pk_default_len) {
                if ((pk_default_len >= 2) && ((pk_default_len % 2) == 0)) {
                    const WCHAR* wptr = reinterpret_cast<const WCHAR*>(pk_default_buf);
                    const size_t wlen = pk_default_len / sizeof(WCHAR);
                    if (buffer_contains_utf16le_ci(wptr, wlen, redhat_sig_wide)) {
                        found_redhat = true;
                    }
                }
                if (!found_redhat) {
                    if (buffer_contains_ascii_ci(pk_default_buf, pk_default_len, redhat_sig_ascii)) {
                        found_redhat = true;
                    }
                }
            }
            if (found_redhat) {
                vma_debug("NVRAM: QEMU/OVMF certificates detected");
                detection_result = core::add(brand_enum::QEMU);
                break;
            }
        } while (false);

        /* Cleanup */
        cleanup(pk_default_buf);
        cleanup(enum_base_buffer);

        if (privilege_state_saved && token_handle) {
            AdjustTokenPrivileges(token_handle, FALSE, &previous_privileges, previous_privileges_size, nullptr, nullptr);
        }

        if (token_handle) {
            CloseHandle(token_handle);
            token_handle = nullptr;
        }

        return detection_result;
    }


    /**
     * @brief Check whether the CPU is genuine and its reported instruction capabilities are not masked
     * @category Windows, x86
     * @implements VM::CPU_HEURISTIC
     */
    [[nodiscard]] static bool cpu_heuristic() {
        bool spoofed = false;
    #if (VMAWARE_X86)
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2);
        const DWORD_PTR old_affinity = SetThreadAffinityMask(current_thread, 1);

        /* 1) Check for commonly disabled instructions on patches and VMs */
        u32 max_leaf = 0, ebx_0 = 0, ecx_0 = 0, edx_0 = 0;
        cpu::cpuid(max_leaf, ebx_0, ecx_0, edx_0, cpu::leaf::basic_info);

        u32 a = 0, b = 0, c = 0, d = 0;
        cpu::cpuid(a, b, c, d, cpu::leaf::features);

        constexpr u32 AES_NI_BIT = 1u << 25;
        const bool aes_support = (c & AES_NI_BIT) != 0;

        alignas(16) unsigned char plaintext[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };
        alignas(16) unsigned char key[16] = {
            0x0F,0x0E,0x0D,0x0C, 0x0B,0x0A,0x09,0x08,
            0x07,0x06,0x05,0x04, 0x03,0x02,0x01,0x00
        };
        alignas(16) unsigned char out[16] = { 0 };

        /* Need to do a lambda wrapper to isolate SEH from the parent function's stack unwinding */
        struct aes_executor {
            #if (VMAWARE_CLANG || VMAWARE_GCC)
                __attribute__((__target__("aes")))
            #endif
            static bool VMAWARE_VECTORCALL check_aes_integrity(const __m128i block, const __m128i key_vec, unsigned char* o, const bool support) {
                __try {
                    __m128i tmp = _mm_xor_si128(block, key_vec);
                    tmp = _mm_aesenc_si128(tmp, key_vec);

                    _mm_storeu_si128(reinterpret_cast<__m128i*>(o), tmp);

                    if (!support) {
                        vma_debug("CPU_HEURISTIC: Hypervisor detected hiding AES capabilities");
                        return true;
                    }
                }
                __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH
                    )
                {
                    if (support) {
                        vma_debug("CPU_HEURISTIC: Hypervisor reports AES, but it is not handled correctly");
                        return true;
                    }
                }
                return false;
            }
        };

        const __m128i block_val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext));
        const __m128i key_val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));

        bool is_spoofed = false;

        if (aes_executor::check_aes_integrity(block_val, key_val, out, aes_support)) {
            is_spoofed = true;
        }

        /* Detect spoofed AVX state */
        constexpr u32 CPUID1_OSXSAVE = 1u << 27;
        constexpr u32 CPUID1_AVX = 1u << 28;

        constexpr u32 CPUID7_AVX2 = 1u << 5;
        constexpr u32 CPUID7_AVX512F = 1u << 16;

        constexpr u64 XCR0_AVX_MASK = 0x6u;   /* XMM + YMM */
        constexpr u64 XCR0_AVX512_MASK = 0xE6u;  /* XMM + YMM + Opmask + ZMM_Hi256 + Hi16_ZMM */

        const bool avx_adv = (c & CPUID1_AVX) != 0;
        const bool osxsave_adv = (c & CPUID1_OSXSAVE) != 0;

        /*
         * Due to this, it only triggers if a hypervisor has misconfigured its CPUID emulation
         * (e.g., leaving AVX enabled in CPUID but disabling XSAVE or failing to emulate _xgetbv correctly)
         */
        u32 a7 = 0, b7 = 0, c7 = 0, d7 = 0;
        if (max_leaf >= 7u) {
            cpu::cpuid(a7, b7, c7, d7, cpu::leaf::ext_features, 0u);
        }

        const bool avx2_adv = (b7 & CPUID7_AVX2) != 0;
        const bool avx512_adv = (b7 & CPUID7_AVX512F) != 0;

        /* Probe AVX */
        auto is_avx_spoofed = [&]() VMAWARE_TARGET_AVX noexcept -> bool {
            /* If hardware doesn't advertise AVX, we cannot test it in user-mode */
            if (!avx_adv) {
                return false;
            }

            /*
             * If the OS has not enabled XSAVE/XRSTOR, AVX cannot run
             * This is normal bare-metal OS behavior (e.g. legacy/minimal bootloader environments)
             */
            if (!osxsave_adv) {
                return false;
            }

            alignas(32) float in0[8] = { 1,2,3,4,5,6,7,8 };
            alignas(32) float in1[8] = { 16,15,14,13,12,11,10,9 };
            alignas(32) float out[8] = {};

            __try {
                /* Since CPUID reports OSXSAVE as active, xgetbv is guaranteed to work */
                const u64 xcr0 = static_cast<u64>(_xgetbv(0));
                /*
                 * If the OS has not enabled AVX state tracking in XCR0, AVX cannot execute
                 * If a hypervisor misconfigures this, the xgetbv instruction itself will #UD here
                 */
                if ((xcr0 & XCR0_AVX_MASK) != XCR0_AVX_MASK) {
                    return false;
                }

                const __m256 va = _mm256_loadu_ps(in0);
                const __m256 vb = _mm256_loadu_ps(in1);
                const __m256 vc = _mm256_add_ps(va, vb);
                _mm256_storeu_ps(out, vc);
                return out[0] != 17.0f;
            }
            __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH)
            {
                /*
                 * CPUID says AVX is supported, OSXSAVE is enabled, and XCR0 has the AVX state bit
                 * An illegal instruction exception here is architecturally impossible
                 */
                vma_debug("CPU_HEURISTIC: Hypervisor detected hiding AVX capabilities");
                return true;
            }
        };

        /* Probe AVX2 */
        auto is_avx2_spoofed = [&]() VMAWARE_TARGET_AVX2 noexcept -> bool{
            if (!avx2_adv) {
                return false;
            }
            if (!avx_adv || !osxsave_adv) {
                return false;
            }

            alignas(32) u32 in0[8] = { 1,2,3,4,5,6,7,8 };
            alignas(32) u32 in1[8] = { 16,15,14,13,12,11,10,9 };
            alignas(32) u32 out[8] = {};

            __try {
                const u64 xcr0 = static_cast<u64>(_xgetbv(0));
                if ((xcr0 & XCR0_AVX_MASK) != XCR0_AVX_MASK) {
                    return false;
                }

                const __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in0));
                const __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in1));
                const __m256i vc = _mm256_add_epi32(va, vb);
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), vc);
                return out[0] != 17u;
            }
            __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH)
            {
                vma_debug("CPU_HEURISTIC: Hypervisor detected hiding AVX2 capabilities");
                return true;
            }
        };

        /* Probe AVX512 */
        auto is_avx512_spoofed = [&]() VMAWARE_TARGET_AVX512 noexcept -> bool{
            if (!avx512_adv) {
                return false;
            }
            if (!avx_adv || !osxsave_adv) {
                return false;
            }

            alignas(64) u32 in0[16] = {
                1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16
            };
            alignas(64) u32 in1[16] = {
                16,15,14,13,12,11,10,9, 8,7,6,5,4,3,2,1
            };
            alignas(64) u32 out[16] = {};

            __try {
                const u64 xcr0 = static_cast<u64>(_xgetbv(0));

                /*
                 * If the OS disabled AVX-512 state tracking (e.g. kernel flags or hybrid cores)
                 * we return false. Running AVX-512 would legitimately #UD here
                 */
                if ((xcr0 & XCR0_AVX512_MASK) != XCR0_AVX512_MASK) {
                    return false;
                }

                const __m512i va = _mm512_loadu_si512(reinterpret_cast<const void*>(in0));
                const __m512i vb = _mm512_loadu_si512(reinterpret_cast<const void*>(in1));
                const __m512i vc = _mm512_add_epi32(va, vb);
                _mm512_storeu_si512(reinterpret_cast<void*>(out), vc);
                return out[0] != 17u;
            }
            __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH)
            {
                vma_debug("CPU_HEURISTIC: Hypervisor detected hiding AVX512 capabilities");
                return true;
            }
        };

        if (!is_spoofed) {
            if (is_avx_spoofed() || is_avx2_spoofed() || is_avx512_spoofed()) {
                is_spoofed = true;
            }
        }

        if (old_affinity != 0) {
            SetThreadAffinityMask(current_thread, old_affinity);
        }

        if (is_spoofed) {
            return true;
        }

        /* 2. Test if the CPU vendor is spoofed (for example, a CPU reports being AMD in CPUID, but it is Intel) */
        /*
            For this task, we want a instruction that:
            1. It is vendor-only, meaning that other CPU vendors never implemented the same instruction on their microcode
                -> Note: Even if an instruction is vendor-only, it may be treated as a NOP by other CPU vendors, we don't want this
            2. Is compatible enough, meaning both old and new CPUs of this vendor have it
            3. Is enabled by default, without needing BIOS/OS changes
            4. Never switches to kernel-mode, so that is harder to intercept
            5. Is not deprecated today
            6. Its side-effects can be measured from CPL3 (user-mode)

            On Intel, most options are unreliable:
            SGX are deprecated and disabled by default, MPX is deprecated and treated as NOP even in AMD CPUs, AVX-512 is not found in all processors (and AMD integrated part of this set), etc
            On AMD, 3dNow! could be an option, but since its being deprecated, CLZERO fits this criteria better

            So for example, if the CPU reports being Intel, and succesfully runs CLZERO without a NOP, then it's not an Intel CPU.
        */

    #if (VMAWARE_X86_64)
        /* Mov rax, imm64 (10 bytes) + clzero (3 bytes) + ret (1 byte) */
        u8 amd_bytes[] = {
            0x48, 0xB8,                 /* mov rax, imm64 */
            0x00, 0x00, 0x00, 0x00,     /* imm64 low bytes (placeholder) */
            0x00, 0x00, 0x00, 0x00,     /* imm64 high bytes (placeholder) */
            0x0F, 0x01, 0xFC,           /* clzero */
            0xC3                        /* ret */
        };
    #else
        /* Mov eax, imm32 (5 bytes) + clzero (3 bytes) + ret (1 byte) */
        u8 amd_bytes[] = {
            0xB8,                       /* mov eax, imm32 */
            0x00, 0x00, 0x00, 0x00,     /* imm32 (placeholder) */
            0x0F, 0x01, 0xFC,           /* clzero */
            0xC3                        /* ret */
        };
    #endif
        SIZE_T amd_stub_size = sizeof(amd_bytes);

        const u8* bytes = nullptr;
        SIZE_T code_size = 0;

        LPVOID amd_target_mem = nullptr;
        LPVOID exec_mem = nullptr;
        PVOID free_base = nullptr;
        SIZE_T free_size = 0;

        const bool claimed_amd = cpu::is_amd();
        const bool claimed_intel = cpu::is_intel();

        if (!claimed_amd && !claimed_intel) {
            vma_debug("CPU_HEURISTIC: x86 CPU vendor was not recognized as either Intel or AMD");
            return false; /* Zhaoxin? VIA/Centaur? */
        }

        bool proceed = true;
        bool exception = false;

        /*
         * A case where this check could false flag is when analyzing the AMD PRO A8-9600B CPU
         * is based on the "Bristol Ridge" platform, which uses the Excavator microarchitecture (the 4th and final generation of the Bulldozer family)
         * Excavator CPUs do not possess the CLZERO instruction
         */
        if (claimed_amd) {
            cpu::model_struct model = cpu::get_model();
            if (!model.is_ryzen) {
                vma_debug("CPU_HEURISTIC: CPU is AMD but not Ryzen. Skipping CLZERO check");
                proceed = false;
            }
        }

        if (claimed_intel || !claimed_amd) {
            exception = true; /* should generate an exception rather than be treated as a NOP, but we will check its side effects anyways */
        }

        /* One cache line = 64 bytes */
        const SIZE_T target_size = 64;
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_protect_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using nt_flush_instruction_cache_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);

        const auto nt_allocate_virtual_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[0]);
        const auto nt_protect_virtual_memory = reinterpret_cast<nt_protect_virtual_memory_fn>(functions[1]);
        const auto nt_flush_instruction_cache = reinterpret_cast<nt_flush_instruction_cache_fn>(functions[2]);
        const auto nt_free_virtual_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[3]);

        if (!nt_allocate_virtual_memory || !nt_protect_virtual_memory || !nt_flush_instruction_cache || !nt_free_virtual_memory) {
            return false;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);

        {
            PVOID base = nullptr;
            SIZE_T sz = target_size;
            NTSTATUS st2 = nt_allocate_virtual_memory(current_process, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(st2) || base == nullptr) {
                proceed = false;
            }
            else {
                amd_target_mem = base;
                std::memset(amd_target_mem, 0xA5, target_size);

                const std::uintptr_t paddr = reinterpret_cast<std::uintptr_t>(amd_target_mem);
            #if (VMAWARE_X86_64)
                const u64 addr = static_cast<u64>(paddr);
                for (u8 i = 0; i < 8; ++i) {
                    amd_bytes[2 + i] = static_cast<u8>((addr >> (i * 8)) & 0xFF);
                }
            #else
                const u32 addr = static_cast<u32>(paddr);
                for (u8 i = 0; i < 4; ++i) {
                    amd_bytes[1 + i] = static_cast<u8>((addr >> (i * 8)) & 0xFF);
                }
            #endif
                bytes = amd_bytes;
                code_size = amd_stub_size;
            }
        }

        if (proceed) {
            PVOID base = nullptr;
            SIZE_T sz = code_size;
            NTSTATUS st2 = nt_allocate_virtual_memory(current_process, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st2) && base != nullptr) {
                exec_mem = base;
                std::memcpy(exec_mem, bytes, code_size);

                /* Change to RX */
                ULONG old_protection = 0;
                PVOID tmp_base = exec_mem;
                SIZE_T tmp_sz = code_size;
                st2 = nt_protect_virtual_memory(current_process, &tmp_base, &tmp_sz, PAGE_EXECUTE_READ, &old_protection);
                if (NT_SUCCESS(st2)) {
                    nt_flush_instruction_cache(current_process, exec_mem, code_size);

                    using code_func = void(*)();
                    using runner_func = u8(*)(code_func);
                    runner_func runner = +[](code_func func) -> u8 {
                        __try {
                            func();
                            return 0;
                        }
                        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                            return 1;
                        }
                    };

                    const u8 runner_rc = runner(reinterpret_cast<code_func>(exec_mem));

                    /* Check if the target buffer was written to zero by CLZERO */
                    bool memory_all_zero = false;
                    if (amd_target_mem) {
                        volatile u8* p = reinterpret_cast<volatile u8*>(amd_target_mem);
                        memory_all_zero = true;
                        for (SIZE_T i = 0; i < target_size; ++i) {
                            if (p[i] != 0) { 
                                memory_all_zero = false; 
                                break; 
                            }
                        }
                    }

                    if (runner_rc == 0 && exception) {
                        /* Only treat as spoofed if the CLZERO execution actually zeroed the target memory */
                        if (memory_all_zero) {
                            vma_debug("CPU_HEURISTIC: CPU reports being Intel, but VMAware detected a hypervisor running an AMD CPU in the host"); /* or another CPU vendor */
                            spoofed = true;
                        }
                        else {
                            vma_debug("CPU_HEURISTIC: CLZERO returned without exception but target memory was NOT zeroed (NOP/emulated)");
                        }
                    }
                    else if (runner_rc == 1 && !exception) {
                        vma_debug("CPU_HEURISTIC: CPU reports being AMD, but VMAware detected a hypervisor running an Intel CPU in the host"); /* or another CPU vendor */
                        spoofed = true;
                    }
                    else if (runner_rc == 0 && !exception) {
                        if (!memory_all_zero) {
                            vma_debug("CPU_HEURISTIC: CPU reports being AMD, CLZERO executed but did NOT zero the target memory");
                            spoofed = true;
                        }
                    }
                }
            }
        }

        if (exec_mem) {
            free_base = exec_mem; free_size = 0;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            exec_mem = nullptr;
        }
        if (amd_target_mem) {
            free_base = amd_target_mem; free_size = 0;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            amd_target_mem = nullptr;
        }

        if (spoofed) {
            return spoofed;
        }

        /* So if the CPU is Intel, the motherboard should be Intel aswell (and same with AMD) */
        static constexpr u32 VID_INTEL = 0x8086;
        static constexpr u32 VID_AMD_MICRO = 0x1022; /* AMD Core Motherboard / Chipset / Root Complex / PSP */
        static constexpr u32 VID_AMD_ATI = 0x1002; /* AMD / ATI Graphics & legacy display controllers */

        enum class motherboard_vendor { Unknown = 0, Intel = 1, AMD = 2 };

        auto detect_motherboard = []() noexcept -> motherboard_vendor {
            HDEVINFO handle_dev_info = SetupDiGetClassDevsW(
                nullptr,
                L"PCI",
                nullptr,
                DIGCF_ALLCLASSES | DIGCF_PRESENT
            );

            if (handle_dev_info == INVALID_HANDLE_VALUE) {
                return motherboard_vendor::Unknown;
            }

            auto parse_hex4 = [](const wchar_t* p) noexcept -> u32 {
                u32 val = 0;
                for (int i = 0; i < 4; ++i) {
                    const wchar_t c = p[i];
                    u32 nib;
                    if (c >= L'0' && c <= L'9') {
                        nib = static_cast<u32>(c - L'0');
                    }
                    else if ((c | 0x20) >= L'a' && (c | 0x20) <= L'f') {
                        nib = static_cast<u32>((c | 0x20) - L'a' + 10);
                    }
                    else {
                        return 0;
                    }
                    val = (val << 4) | nib;
                }
                return val;
            };

            SP_DEVINFO_DATA dev_info_data{};
            dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

            wchar_t instance_id[256];
            int intel_hits = 0;
            int amd_hits = 0;

            for (DWORD i = 0; SetupDiEnumDeviceInfo(handle_dev_info, i, &dev_info_data); ++i) {
                if (SetupDiGetDeviceInstanceIdW(handle_dev_info, &dev_info_data, instance_id, ARRAYSIZE(instance_id), nullptr)) {
                    if (((instance_id[0] | 0x20) == L'p') &&
                        ((instance_id[1] | 0x20) == L'c') &&
                        ((instance_id[2] | 0x20) == L'i') &&
                        (instance_id[3] == L'\\') &&
                        ((instance_id[4] | 0x20) == L'v') &&
                        ((instance_id[5] | 0x20) == L'e') &&
                        ((instance_id[6] | 0x20) == L'n') &&
                        (instance_id[7] == L'_')) {

                        const u32 vid = parse_hex4(instance_id + 8);
                        if (vid == VID_INTEL) {
                            intel_hits++;
                        }
                        else if (vid == VID_AMD_MICRO) {
                            amd_hits += 2;
                        }
                        else if (vid == VID_AMD_ATI) {
                            amd_hits += 1;
                        }
                    }
                }
            }

            SetupDiDestroyDeviceInfoList(handle_dev_info);

            /* Motherboard chipsets provide 10-40+ integrated PCI devices */
            /* Add-in cards (like Intel Wi-Fi on AMD board, or AMD GPU on Intel board) should only provide like 1-3 devices */
            if (intel_hits >= 3 && intel_hits > amd_hits * 2) {
                return motherboard_vendor::Intel;
            }
            if (amd_hits >= 3 && amd_hits > intel_hits * 2) {
                return motherboard_vendor::AMD;
            }

            return motherboard_vendor::Unknown;
        };

        const motherboard_vendor vendor = detect_motherboard();

        switch (vendor) {
        case motherboard_vendor::Intel:
            if (claimed_amd && !claimed_intel) {
                vma_debug("CPU_HEURISTIC: CPU reports AMD but chipset looks Intel");
                spoofed = true;
            }
            break;
        case motherboard_vendor::AMD:
            if (claimed_intel && !claimed_amd) {
                vma_debug("CPU_HEURISTIC: CPU reports Intel but chipset looks AMD");
                spoofed = true;
            }
            break;
        case motherboard_vendor::Unknown:
            vma_debug("CPU_HEURISTIC: Could not determine chipset vendor");
            break;
        default:
            VMAWARE_ASSUME(0);
        }
    #endif
        return spoofed;
    }


    /**
     * @brief Check for the absence of system timers
     * @category x86, Windows
     * @implements VM::CLOCK
     */
    [[nodiscard]] static bool clock() {
    #if (VMAWARE_ARM)
        return false; /* ARM systems do not have the classic x86 timers */
    #else   
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        const char* manufacturer = nullptr;
        const char* model = nullptr;

        if (util::get_manufacturer_model(&manufacturer, &model)) {
            const bool is_surface = string::contains_ci(model, "Surface");
            const bool is_microsoft = string::contains_ci(manufacturer, "Microsoft");
            const bool is_xiaomi = string::contains_ci(manufacturer, "XIAOMI");

            if ((is_surface && is_microsoft) || is_xiaomi) {
                vma_debug("Surface or Xiaomi device found, aborting PIT/AT check");
                return false;
            }
        }

        const HDEVINFO devs = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (devs == INVALID_HANDLE_VALUE) {
            return false;
        }

        SP_DEVINFO_DATA dev_info{};
        dev_info.cbSize = sizeof(dev_info);

        BYTE* buffer = nullptr;
        DWORD buffer_size = 0;
        bool found = false;

        for (DWORD i = 0; SetupDiEnumDeviceInfo(devs, i, &dev_info); ++i) {
            DWORD type = 0;
            DWORD needed = 0;

            if (SetupDiGetDeviceRegistryPropertyW(
                devs, &dev_info, SPDRP_HARDWAREID,
                &type, nullptr, 0, &needed)) {
                continue;
            }

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
                continue;
            }

            #define DWORD_MAX 4294967295
            if (needed > (DWORD_MAX - sizeof(wchar_t))) {
                continue;
            }

            if (needed + sizeof(wchar_t) > buffer_size) {
                DWORD new_size = needed + sizeof(wchar_t);
                BYTE* new_buffer = static_cast<BYTE*>(realloc(buffer, new_size));

                if (!new_buffer) {
                    free(buffer);
                    SetupDiDestroyDeviceInfoList(devs);
                    return false;
                }

                buffer = new_buffer;
                buffer_size = new_size;
            }

            if (!SetupDiGetDeviceRegistryPropertyW(
                devs, &dev_info, SPDRP_HARDWAREID,
                &type, buffer, buffer_size, &needed)) {
                continue;
            }

            if (type != REG_MULTI_SZ) {
                continue;
            }

            if (buffer != nullptr) {
                reinterpret_cast<wchar_t*>(buffer)[needed / sizeof(wchar_t)] = L'\0';
            }

            const wchar_t* const buffer_start = reinterpret_cast<const wchar_t*>(buffer);
            const wchar_t* const buffer_end = buffer_start + (needed / sizeof(wchar_t));

            for (const wchar_t* s = buffer_start; s < buffer_end && *s; s += wcslen(s) + 1) {
                if (_wcsicmp(s, L"ACPI\\PNP0100") == 0 ||
                    _wcsicmp(s, L"PNP0100") == 0) {
                    found = true;
                    break;
                }
            }

            if (found) {
                break;
            }
        }

        free(buffer);
        SetupDiDestroyDeviceInfoList(devs);
        return !found;
    #endif  
    }


    /**
     * @brief Check whether the hypervisor mishandles MSR behavior
     * @category Windows, x86
     * @implements VM::MSR
     */
    [[nodiscard]] static bool msr() {
    #if (!VMAWARE_X86)
        return false;
    #else
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        constexpr u32 random_msr = 0xDEADBEEFu;

    #if (VMAWARE_GCC || VMAWARE_CLANG) 
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) return false;

        constexpr const char* function_names[] = {
            "RtlAddVectoredExceptionHandler",
            "RtlRemoveVectoredExceptionHandler"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using rtl_add_vectored_exception_handler_fn = PVOID(__stdcall*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
        using rtl_remove_vectored_exception_handler_fn = ULONG(__stdcall*)(PVOID);

        static rtl_add_vectored_exception_handler_fn volatile rtl_add_vectored_exception_handler = reinterpret_cast<rtl_add_vectored_exception_handler_fn>(functions[0]);
        static rtl_remove_vectored_exception_handler_fn volatile rtl_remove_vectored_exception_handler = reinterpret_cast<rtl_remove_vectored_exception_handler_fn>(functions[1]);

        if (!rtl_add_vectored_exception_handler || !rtl_remove_vectored_exception_handler) {
            return false;
        }
    #endif

        auto try_read = [](const u32 msr_index) noexcept -> bool {
        #if (VMAWARE_MSVC && !VMAWARE_CLANG)
            unsigned __int64 value = 0;
            __try {
                value = __readmsr(static_cast<unsigned long>(msr_index));
                VMAWARE_UNUSED(value);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        #elif (VMAWARE_GCC || VMAWARE_CLANG)
            static thread_local bool g_msr_faulted = false;
            g_msr_faulted = false;

            auto veh_handler = [](PEXCEPTION_POINTERS info) noexcept -> LONG {
                if (info->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
                    g_msr_faulted = true;
                    /* Skip the 'rdmsr' instruction (2 bytes: 0F 32) */
                #if (VMAWARE_X86_64)
                    info->ContextRecord->Rip += 2;
                #else
                    info->ContextRecord->Eip += 2;
                #endif
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                return EXCEPTION_CONTINUE_SEARCH;
             };

            const PVOID handle = rtl_add_vectored_exception_handler(1, veh_handler);

            u32 low = 0, high = 0;
            asm volatile (
                "rdmsr"
                : "=a"(low), "=d"(high)
                : "c"(msr_index)
             );

            rtl_remove_vectored_exception_handler(handle);

            return !g_msr_faulted;
        #endif
        };

        auto try_write = [](const u32 msr_index, const unsigned __int64 value) noexcept -> bool {
        #if (VMAWARE_MSVC && !VMAWARE_CLANG)
            __try {
                __writemsr(static_cast<unsigned long>(msr_index), value);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        #elif (VMAWARE_GCC || VMAWARE_CLANG)
            static thread_local bool g_msr_write_faulted = false;
            g_msr_write_faulted = false;

            auto veh_handler = [](PEXCEPTION_POINTERS info) noexcept -> LONG {
                if (info->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
                    g_msr_write_faulted = true;
                    /* Skip the 'wrmsr' instruction (2 bytes: 0F 30) */
                #if (VMAWARE_X86_64)
                    info->ContextRecord->Rip += 2;
                #else
                    info->ContextRecord->Eip += 2;
                #endif
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                return EXCEPTION_CONTINUE_SEARCH;
            };

            const PVOID handle = rtl_add_vectored_exception_handler(1, veh_handler);

            u32 low = static_cast<u32>(value & 0xFFFFFFFF);
            u32 high = static_cast<u32>(value >> 32);
            asm volatile (
                "wrmsr"
                :
            : "c"(msr_index), "a"(low), "d"(high)
            );

            rtl_remove_vectored_exception_handler(handle);

            return !g_msr_write_faulted;
        #endif
        };

        if (try_read(random_msr)) {
            vma_debug("MSR: Detected hypervisor not correctly handling #GP on read");
            return true;
        }

        if (try_write(random_msr, 0ULL)) {
            vma_debug("MSR: Detected hypervisor not correctly handling #GP on write");
            return true;
        }

        return false;
    #endif
    }


    /**
     * @brief Check whether KVM attempts to patch a mismatched hypercall instruction
     * @link https://lists.nongnu.org/archive/html/qemu-devel/2025-07/msg05044.html
     * @category Windows, x86
     * @implements VM::KVM_INTERCEPTION
     */
    [[nodiscard]] static bool kvm_interception() {
    #if (!VMAWARE_X86)
        return false;
    #else
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        const void* stubs[2] = { vmcall_stub, vmmcall_stub };
        bool is_kvm_detected = false;
        bool generic_hypervisor = false;

        for (int i = 0; i < 2; ++i) {
            const DWORD exception_status = memory::execute_handler(stubs[i]);
            const bool fault_hit = (exception_status != 0);

            if (!fault_hit) {
                /* If no exception occurs, then a hypervisor intercepted and handled it */
                generic_hypervisor = true;
                vma_debug("KVM_INTERCEPTION: Detected a hypervisor intercepting hypercalls");
            }
            else if (exception_status == EXCEPTION_ACCESS_VIOLATION || exception_status == EXCEPTION_IN_PAGE_ERROR) {
                /* Expected #UD became a page-fault-related exception instead. KVM's instruction patching quirk is present */
                vma_debug("KVM_INTERCEPTION: Detected KVM attempting to patch instructions on the fly");
                is_kvm_detected = true;
            }

            if (is_kvm_detected) {
                return core::add(brand_enum::KVM);
            }
            else if (generic_hypervisor) {
                return true;
            }
        }

        return false;
    #endif
    }


    /**
     * @brief Check whether a hypervisor uses EPT/NPT hooking to intercept hardware breakpoints
     * @note This hypervisor detection also affects debuggers
     * @category Windows, x86
     * @author @NickEverdox (https://github.com/everdox) - ERMSB check
     * @implements VM::HYPERVISOR_HOOK
     */
    [[nodiscard]] static bool hypervisor_hook() {
    #if (!VMAWARE_X86)
        return false;
    #else
        #if (defined VMAWARE_DEBUG)
            if (IsDebuggerPresent()) {
                return false; /* To not hit the debugger breakpoint, making the debugger impossible to advance */
            }
        #endif  
        if (util::is_x86_process_on_arm()) {
            return false;
        }
        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = {
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtGetContextThread",
            "NtSetContextThread",
            "RtlAddVectoredExceptionHandler",
            "RtlRemoveVectoredExceptionHandler",
            "NtProtectVirtualMemory",
            "NtQuerySystemInformation",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
            "NtClose",
            "NtSetInformationThread",
            "NtFlushInstructionCache"
        };
        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using net_get_context_thread_fn = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using nt_set_context_thread_fn = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using rtl_add_vectored_exception_handler_fn = PVOID(__stdcall*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
        using rtl_remove_vectored_exception_handler_fn = ULONG(__stdcall*)(PVOID);
        using nt_protect_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using nt_query_system_information_fn = NTSTATUS(__stdcall*)(ULONG, PVOID, ULONG, PULONG);
        using nt_create_thread_ex_fn = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
        using nt_wait_for_single_object_fn = NTSTATUS(__stdcall*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        using nt_close_fn = NTSTATUS(__stdcall*)(HANDLE);
        using nt_set_information_thread_fn = NTSTATUS(__stdcall*)(HANDLE, ULONG, PVOID, ULONG);
        using nt_flush_instruction_cache_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);

        /* Volatile ensures these are loaded from stack after SEH unwind when compiled with aggressive optimizations */
        nt_allocate_virtual_memory_fn volatile nt_allocate_virtual_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[0]);
        nt_free_virtual_memory_fn volatile nt_free_virtual_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[1]);
        net_get_context_thread_fn volatile nt_get_context_thread = reinterpret_cast<net_get_context_thread_fn>(functions[2]);
        nt_set_context_thread_fn volatile nt_set_context_thread = reinterpret_cast<nt_set_context_thread_fn>(functions[3]);
        rtl_add_vectored_exception_handler_fn volatile rtl_add_vectored_exception_handler = reinterpret_cast<rtl_add_vectored_exception_handler_fn>(functions[4]);
        rtl_remove_vectored_exception_handler_fn volatile rtl_remove_vectored_exception_handler = reinterpret_cast<rtl_remove_vectored_exception_handler_fn>(functions[5]);
        nt_protect_virtual_memory_fn volatile nt_protect_virtual_memory = reinterpret_cast<nt_protect_virtual_memory_fn>(functions[6]);
        nt_query_system_information_fn volatile nt_query_system_information = reinterpret_cast<nt_query_system_information_fn>(functions[7]);
        nt_create_thread_ex_fn volatile nt_create_thread_ex = reinterpret_cast<nt_create_thread_ex_fn>(functions[8]);
        nt_wait_for_single_object_fn volatile nt_wait_for_single_object = reinterpret_cast<nt_wait_for_single_object_fn>(functions[9]);
        nt_close_fn volatile nt_close = reinterpret_cast<nt_close_fn>(functions[10]);
        nt_set_information_thread_fn volatile nt_set_information_thread = reinterpret_cast<nt_set_information_thread_fn>(functions[11]);
        nt_flush_instruction_cache_fn volatile nt_flush_instruction_cache = reinterpret_cast<nt_flush_instruction_cache_fn>(functions[12]);

        if (!nt_allocate_virtual_memory || !nt_free_virtual_memory || !nt_get_context_thread ||
            !nt_set_context_thread || !rtl_add_vectored_exception_handler || !rtl_remove_vectored_exception_handler ||
            !nt_protect_virtual_memory || !nt_query_system_information || !nt_create_thread_ex ||
            !nt_wait_for_single_object || !nt_close || !nt_set_information_thread ||
            !nt_flush_instruction_cache) {
            return false;
        }

        HANDLE current_process = reinterpret_cast<HANDLE>(-1);
        HANDLE current_thread = reinterpret_cast<HANDLE>(-2);
        GROUP_AFFINITY original_affinity{};
        if (!GetThreadGroupAffinity(current_thread, &original_affinity)) {
            return false;
        }

        using find_double_cc_ntdll_fn = void* (*)(HMODULE);
        find_double_cc_ntdll_fn find_double_cc_ntdll = [](HMODULE module) noexcept -> void* {
            if (!module) {
                return nullptr;
            }

            /* Parse PE headers to find executable sections */
            auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                return nullptr;
            }

            auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<u8*>(module) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                return nullptr;
            }

            auto* section = IMAGE_FIRST_SECTION(nt_headers);
            for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
                /* Only scan memory marked as executable */
                if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                    u8* ptr = reinterpret_cast<u8*>(module) + section->VirtualAddress;
                    const size_t size = section->Misc.VirtualSize;

                    if (size < 2) {
                        continue;
                    }

                    for (size_t j = 0; j < size - 1; ++j) {
                        VMAWARE_PREFETCH(&ptr[j + 64], _MM_HINT_T0);
                        if (ptr[j] == 0xCC && ptr[j + 1] == 0xCC) {
                            /*
                             * By returning ptr[j + 1], executing it will safely run 0xC3 (after overwrite)
                             * if we overwrite j+1 with 0xC3 and call it, it immediately returns
                             */
                            return &ptr[j + 1];
                        }
                    }
                }
            }
            return nullptr;
        };

        using find_double_cc_fn = void* (*)(void*);
        find_double_cc_fn find_double_cc = [](void* pointer_in_page) noexcept -> void* {
            /* Align down to the start of the 4KB page */
            auto* ptr = reinterpret_cast<u8*>(reinterpret_cast<uintptr_t>(pointer_in_page) & ~0xFFF);

            for (size_t i = 0; i < (0x1000 - 1); ++i) {
                if (ptr[i] == 0xCC && ptr[i + 1] == 0xCC) {
                    return &ptr[i + 1];
                }
            }
            return nullptr;
        };

        void* pointer = find_double_cc_ntdll(ntdll);
        if (!pointer) {
            void* current_func_ptr = reinterpret_cast<void*>(&hypervisor_hook);
            pointer = find_double_cc(current_func_ptr);
            if (!pointer) {
                return false;
            }
        }

        /* Executing CC natively should throw */
        if (!memory::execute_handler(pointer)) {
            return false; /* SEH is broken or code isn't actually CC */
        }

        /* Overwrite CC with C3 (RET) */
        PVOID base_address = pointer;
        SIZE_T prot_region_size = 1;
        ULONG old_protect = 0;

        /*
         * NtProtectVirtualMemory modifies BaseAddress and RegionSize to page boundaries,
         * so we must reset them on subsequent calls
         */
        NTSTATUS status = nt_protect_virtual_memory(current_process, &base_address, &prot_region_size, PAGE_EXECUTE_READWRITE, &old_protect);
        if (status < 0) {
            return false;
        }

        *static_cast<volatile u8*>(pointer) = 0xC3;
        nt_flush_instruction_cache(current_process, const_cast<void*>(pointer), 1);

        base_address = pointer;
        prot_region_size = 1;
        ULONG dummy_protect = 0;
        status = nt_protect_virtual_memory(current_process, &base_address, &prot_region_size, old_protect, &dummy_protect);
        if (status < 0) { 
            return false; 
        }

        bool hook_detected = false;

        /* Test if write was swallowed by the hypervisor on the current core */
        if (memory::execute_handler(pointer)) {
            hook_detected = true;
        }
        else {
            volatile LONG did_anyone_throw = 0;
            GROUP_AFFINITY active_group_aff{};

            if (GetThreadGroupAffinity(current_thread, &active_group_aff)) {
                for (ULONG i = 0; i < 64; ++i) {
                    if (active_group_aff.Mask & ((ULONG_PTR)1 << i)) {
                        GROUP_AFFINITY target_aff = active_group_aff;
                        target_aff.Mask = (ULONG_PTR)1 << i;

                        if (SetThreadGroupAffinity(current_thread, &target_aff, nullptr)) {
                            __try {
                                memory::execute(pointer);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                did_anyone_throw = 1;
                            }
                        }
                    }
                }
                SetThreadGroupAffinity(current_thread, &original_affinity, nullptr);
            }

            if (did_anyone_throw != 0) {
                hook_detected = true;
            }
        }

        PVOID src_page = nullptr;
        PVOID dst_page = nullptr;
        SIZE_T region_size = 0x2000;

        /* Allocate source and destination pages */
        const NTSTATUS status_src = nt_allocate_virtual_memory(current_process, &src_page, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        const NTSTATUS status_dst = nt_allocate_virtual_memory(current_process, &dst_page, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (status_src < 0 || status_dst < 0) {
            if (src_page) {
                SIZE_T free_size = 0;
                nt_free_virtual_memory(current_process, &src_page, &free_size, MEM_RELEASE);
            }
            if (dst_page) {
                SIZE_T free_size = 0;
                nt_free_virtual_memory(current_process, &dst_page, &free_size, MEM_RELEASE);
            }
            return false;
        }

        /* Initialize src memory */
        __stosb(static_cast<PBYTE>(src_page), 0xAB, 0x2000);

        thread_local static volatile bool ermsb_trap_detected = false;
        ermsb_trap_detected = false;

        struct exception_handler {
            static VMAWARE_NOINLINE LONG __stdcall execute(const PEXCEPTION_POINTERS ctx) {
                if (ctx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    ermsb_trap_detected = true;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        const PVOID veh_handle = rtl_add_vectored_exception_handler(1, exception_handler::execute);
        if (!veh_handle) {
            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &src_page, &free_size, MEM_RELEASE);
            nt_free_virtual_memory(current_process, &dst_page, &free_size, MEM_RELEASE);
            return false;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        status = nt_get_context_thread(current_thread, &ctx);

        if (status < 0) {
            rtl_remove_vectored_exception_handler(veh_handle);
            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &src_page, &free_size, MEM_RELEASE);
            nt_free_virtual_memory(current_process, &dst_page, &free_size, MEM_RELEASE);
            return false;
        }

        /* Set hw breakpoint inside the source page */
        ctx.Dr0 = reinterpret_cast<DWORD64>(src_page) + 0x1000;

        /*
         * Dr7 = 0x30001
         * bit 0      = 1
         * bits 17:16 = 11b
         * bits 19:18 = 00b
         */
        ctx.Dr7 = 0x30001;
        status = nt_set_context_thread(current_thread, &ctx);
        if (status < 0) {
            rtl_remove_vectored_exception_handler(veh_handle);
            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &src_page, &free_size, MEM_RELEASE);
            nt_free_virtual_memory(current_process, &dst_page, &free_size, MEM_RELEASE);
            return false;
        }

        __try {
            __movsb(static_cast<PBYTE>(dst_page), static_cast<PBYTE>(src_page), 0x2000);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* VEH will already detect if Dr0 fired successfully */
        }

        rtl_remove_vectored_exception_handler(veh_handle);

        ctx.Dr0 = 0;
        ctx.Dr7 = 0;
        nt_set_context_thread(current_thread, &ctx);

        SIZE_T free_size = 0;
        nt_free_virtual_memory(current_process, &src_page, &free_size, MEM_RELEASE);
        nt_free_virtual_memory(current_process, &dst_page, &free_size, MEM_RELEASE);

        return hook_detected || !ermsb_trap_detected;
    #endif
    }


    /**
     * @brief Check whether a hypervisor delays trap flags over exiting instructions
     * @category Windows, x86
     * @implements VM::SINGLE_STEP
     */
    [[nodiscard]] static bool single_step() {
    #if (!VMAWARE_X86)
        return false;
    #else
        if (util::hyper_x() == HYPERV_HOST) {
            return false;
        }
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        struct exception_handler {
            static VMAWARE_NOINLINE LONG execute(const EXCEPTION_POINTERS* info, DWORD* exceptionCode) {
                *exceptionCode = info->ExceptionRecord->ExceptionCode;
            #if (VMAWARE_X86_64)
                info->ContextRecord->Rbx = info->ContextRecord->R8;
            #elif (VMAWARE_X86_32)
                info->ContextRecord->Ebx = info->ContextRecord->Edi;
            #endif
                return EXCEPTION_EXECUTE_HANDLER;
            }
        };

        bool cpuid_is_vm = true;
        DWORD exc_code_cpuid = 0;

        __try {
            memory::execute(cpuid_singlestep_stub);
            /* If the hypervisor completely swallows all exceptions, is_vm still remains true */
        }
        __except (exception_handler::execute(GetExceptionInformation(), &exc_code_cpuid)) {
            /*
             * If the exception doesnt reach this block, hypervisor delayed the trap flag over cpuid, execution fell through into
             * the bad bytes (C7 B2) causing STATUS_ILLEGAL_INSTRUCTION
             */
            if (exc_code_cpuid == EXCEPTION_SINGLE_STEP) {
                cpuid_is_vm = false; /* trap flag single-step exception triggered on CPUID */
            }
        }

        bool rdpru_available = false;
        if (!cpuid_is_vm && cpu::is_amd()) {
            u32 a = 0, b = 0, c = 0, d = 0;
            cpu::cpuid(a, b, c, d, cpu::leaf::ext_limits);
            rdpru_available = ((b & (1 << 4)) != 0);
        }
        else {
            return cpuid_is_vm;
        }

        bool rdpru_is_vm = false;

        if (rdpru_available) {
            rdpru_is_vm = true;
            DWORD exc_code_rdpru = 0;

            __try {
                memory::execute(rdpru_singlestep_stub);
            }
            __except (exception_handler::execute(GetExceptionInformation(), &exc_code_rdpru)) {
                if (exc_code_rdpru == EXCEPTION_SINGLE_STEP) {
                    rdpru_is_vm = false;
                }
            }
        }

        return rdpru_is_vm;
    #endif
    }


    /**
     * @brief Check whether a hypervisor does not correctly emulate instructions in compatibility mode
     * @category Windows, x86_64
     * @author Idea by @NickEverdox (https://github.com/everdox)
     * @implements VM::EIP_OVERFLOW
     */
    [[nodiscard]] static bool eip_overflow() {
    #if (!VMAWARE_X86_64) 
        /*
         * This requires mapping executable memory at the end of the 4GB address space (0xFFFF0000) so an instruction can wrap the 32 bit boundary
         * because NtAllocateVirtualMemory will always return 0xC0000018 (STATUS_CONFLICTING_ADDRESSES) we physically cannot place an instruction at 0xFFFFFFFE
         */
        return false;
    #else   
    #pragma pack(push, 1)
        struct iretq_frame {
            u64 ip;
            u64 cs;
        };
    #pragma pack(pop)

        if (util::is_x86_process_on_arm()) {
            return false;
        }
        if (util::is_32bit_execution_disabled()) { /* People may uninstall the WOW64 subsystem */
            return false;
        }

        static_assert(sizeof(iretq_frame) == 16, "iretq_frame size must be exactly 16 bytes for proper hardware exception processing.");
        static_assert(std::is_standard_layout<iretq_frame>::value, "iretq_frame must follow standard layout rules.");

        static bool hypervisor_detected = true;
        static u64 g_saved_rsp = 0;

        const HMODULE ntdll = memory::get_module(true);
        if (!ntdll) {
            return false;
        }

        constexpr const char* function_names[] = {
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "RtlAddVectoredExceptionHandler",
            "RtlRemoveVectoredExceptionHandler"
        };

        void* functions[ARRAYSIZE(function_names)] = {};
        memory::get_function(ntdll, function_names, functions, ARRAYSIZE(function_names));

        using nt_allocate_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_free_virtual_memory_fn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using rtl_add_vectored_exception_handler_fn = PVOID(__stdcall*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
        using rtl_remove_vectored_exception_handler_fn = ULONG(__stdcall*)(PVOID);

        const auto nt_allocate_virtual_memory = reinterpret_cast<nt_allocate_virtual_memory_fn>(functions[0]);
        const auto nt_free_virtual_memory = reinterpret_cast<nt_free_virtual_memory_fn>(functions[1]);
        const auto rtl_add_vectored_exception_handler = reinterpret_cast<rtl_add_vectored_exception_handler_fn>(functions[2]);
        const auto rtl_remove_vectored_exception_handler = reinterpret_cast<rtl_remove_vectored_exception_handler_fn>(functions[3]);

        if (!nt_allocate_virtual_memory || !nt_free_virtual_memory || !rtl_add_vectored_exception_handler || !rtl_remove_vectored_exception_handler) {
            return false;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);

        auto eip_overflow_veh = [](PEXCEPTION_POINTERS exc_info) noexcept -> LONG {
            /* Check for the expected access violation */
            if (exc_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                DWORD64 fault_ip = exc_info->ContextRecord->Rip;
                DWORD cs_reg = exc_info->ContextRecord->SegCs;

                /*
                 * Verify EIP correctly truncated and wrapped to 0x0 in 32-bit mode
                 * if hypervisor only supports x86_64, RIP will be 0x100000000
                 */
                if (fault_ip == 0x0 && cs_reg == 0x23) {
                    hypervisor_detected = false;
                }
            }

            if (g_saved_rsp != 0) {
                /*
                static const unsigned char recover_stub[] = {
                    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5E, 0x5F, 0x5D, 0x5B, // pop r15-r12, rsi, rdi, rbp, rbx
                    0xC3                                                                    // ret
                };
                */
                const u64* saved_stack = reinterpret_cast<const u64*>(g_saved_rsp);
                exc_info->ContextRecord->R15 = saved_stack[0];
                exc_info->ContextRecord->R14 = saved_stack[1];
                exc_info->ContextRecord->R13 = saved_stack[2];
                exc_info->ContextRecord->R12 = saved_stack[3];
                exc_info->ContextRecord->Rsi = saved_stack[4];
                exc_info->ContextRecord->Rdi = saved_stack[5];
                exc_info->ContextRecord->Rbp = saved_stack[6];
                exc_info->ContextRecord->Rbx = saved_stack[7];

                exc_info->ContextRecord->SegCs = 0x33;
                exc_info->ContextRecord->Rip = saved_stack[8];   /* cleanup shellcode */
                exc_info->ContextRecord->Rsp = g_saved_rsp + 72;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        };

        const PVOID handler_ptr = rtl_add_vectored_exception_handler(1, static_cast<PVECTORED_EXCEPTION_HANDLER>(eip_overflow_veh));
        if (!handler_ptr) {
            return false;
        }

        /*
         * Recovery jump target for VEH
         * dynamically allocate a 32-bit compatible stack (must reside below 4GB)
         */
        PVOID stack32_base = nullptr;
        SIZE_T stack32_size = 0x10000;
        for (uintptr_t addr = 0x20000000; addr < 0x80000000; addr += 0x10000000) {
            stack32_base = reinterpret_cast<PVOID>(addr);
            if (nt_allocate_virtual_memory(current_process, &stack32_base, 0, &stack32_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
                break;
            }
            stack32_base = nullptr;
        }

        if (!stack32_base) {
            rtl_remove_vectored_exception_handler(handler_ptr);
            return false;
        }

        /* Align stack pointer */
        const uintptr_t stack32_ptr = reinterpret_cast<uintptr_t>(stack32_base) + 0x10000 - 0x20;

        /* High-boundary 32-bit execution target */
        PVOID boundary_base = reinterpret_cast<PVOID>(0xFFFF0000ULL);
        SIZE_T boundary_size = 0x10000ULL;
        NTSTATUS alloc_status = nt_allocate_virtual_memory(current_process, &boundary_base, 0, &boundary_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (alloc_status >= 0) {
            if (boundary_base == reinterpret_cast<PVOID>(0xFFFF0000ULL)) {
                /* Inject cpuid at the strict end of the compat-mode space */
                u8* execution_target = reinterpret_cast<u8*>(boundary_base) + 0xFFFEULL;

                /* Break Clang static analyzer's tracking of execution_target as a compile-time constant */
            #if (VMAWARE_GCC || VMAWARE_CLANG)
                asm volatile("" : "+r"(execution_target));
            #endif

                execution_target[0] = 0x0F;
                execution_target[1] = 0xA2;

                iretq_frame frame = {};
                frame.ip = 0xFFFFFFFEULL;
                frame.cs = 0x23;

                /* Dispatch hardware context switch shellcode */
                memory::execute(switch_stub, &frame, stack32_ptr, &g_saved_rsp);
            }
            else {
                hypervisor_detected = false;
            }

            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &boundary_base, &free_size, MEM_RELEASE);
        }
        else {
            hypervisor_detected = false;
        }

        SIZE_T free_size = 0;
        nt_free_virtual_memory(current_process, &stack32_base, &free_size, MEM_RELEASE);
        rtl_remove_vectored_exception_handler(handler_ptr);

        return hypervisor_detected;
    #endif  
    }


    /**
     * @brief Check whether a hypervisor leaks EFER.SVME into guest context via SVM instruction fault type
     * @category Windows, x86
     * @implements VM::SVM_EXCEPTIONS
     */
    [[nodiscard]] static bool svm_exceptions() {
    #if (VMAWARE_X86)   
        if (!cpu::is_amd()) {
            vma_debug("SVM_EXCEPTIONS: AMD CPU not detected");
            return false;
        }

        if (util::hyper_x() == HYPERV_HOST) {
            return false;
        }
        if (util::is_x86_process_on_arm()) {
            return false;
        }

        u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
        cpu::cpuid(eax, ebx, ecx, edx, cpu::leaf::proc_ext);
        const bool svm_visible = ((ecx >> 2) & 1) != 0;

        const DWORD exception_status = memory::execute_handler(vmload_stub);
        const bool fault_hit = (exception_status != 0);

        if (exception_status == EXCEPTION_ILLEGAL_INSTRUCTION) {
            return false; /* AMD CPUs only #UD if SVM is not active */
        }

        /* 
         * If we reach here, it means:
         * 1. An exception was triggered, since we're executing at CPL3
         * 2. That exception was not #UD, because the code would have returned in the branch above
         * 3. EFER.SVME is 1, because the exception was not #UD, so SVM is active
         * 
         * If CPUID says SVM is not active (!svm_visible), it contradicts EFER.SVME being 1, it's a red flag
         * If there was no exception at all (!fault_hit), it contradicts our current CPL3 privilege, it's a red flag
         */
        if (!svm_visible || !fault_hit) { /* Hypervisor spoofed call, buggy firmware, or AMD server CPU */
            vma_debug("SVM_EXCEPTIONS: Detected SVM hypervisor hiding CPU capabilities");
            return core::add(brand_enum::NULL_BRAND, 150);
        }

        return true; /* If we reach here, we're sure an exception occurs (fault_hit is true), but was not #UD (must be a #GP), confirming EFER.SVME being 1 */
    #else
        return false;
    #endif  
    }


    /**
     * @brief Check measured boot logs exported by the TPM
     * @category Windows
     * @implements VM::MEASURED_BOOT
     */
    [[nodiscard]] static bool measured_boot() {
        using TBS_RESULT = UINT32;
        using TBS_HCONTEXT = void*;

    #pragma pack(push, 1)
        struct VMAWARE_TBS_CONTEXT_PARAMS {
            UINT32 version;
        };

        struct TCG_PCR_EVENT_HEADER {
            u32 pcrIndex;
            u32 eventType;
            u8  digest[20];
            u32 eventSize;
        };

        struct alg_size {
            u16 algId;
            u16 digestSize;
        };
    #pragma pack(pop)

        static_assert(sizeof(VMAWARE_TBS_CONTEXT_PARAMS) == 4, "VMAWARE_TBS_CONTEXT_PARAMS must be exactly 4 bytes.");
        static_assert(sizeof(TCG_PCR_EVENT_HEADER) == 32, "TCG_PCR_EVENT_HEADER must be exactly 32 bytes.");
        static_assert(sizeof(alg_size) == 4, "alg_size must be exactly 4 bytes.");

        using tbsi_get_tcg_log_ex_fn = TBS_RESULT(__stdcall*)(UINT32, PBYTE, PUINT32);
        using tbsi_context_create_fn = TBS_RESULT(__stdcall*)(const VMAWARE_TBS_CONTEXT_PARAMS*, TBS_HCONTEXT*);
        using tbsip_context_close_fn = TBS_RESULT(__stdcall*)(TBS_HCONTEXT);
        using tbsi_get_tcg_log_fn = TBS_RESULT(__stdcall*)(TBS_HCONTEXT, PBYTE, PUINT32);

        auto parse_log = [](const std::vector<u8>& log_data) noexcept -> bool {
            auto read_u16 = [](const u8* ptr) noexcept -> u16 {
                u16 val = 0;
                std::memcpy(&val, ptr, sizeof(u16));
                return val;
            };

            auto read_u32 = [](const u8* ptr) noexcept -> u32 {
                u32 val = 0;
                std::memcpy(&val, ptr, sizeof(u32));
                return val;
            };

            auto read_u64 = [](const u8* ptr) noexcept -> u64 {
                u64 val = 0;
                std::memcpy(&val, ptr, sizeof(u64));
                return val;
            };

            auto read_alg_size = [](const u8* ptr) noexcept -> alg_size {
                alg_size val = { 0, 0 };
                std::memcpy(&val, ptr, sizeof(alg_size));
                return val;
            };

            auto read_hdr = [](const u8* ptr) noexcept -> TCG_PCR_EVENT_HEADER {
                TCG_PCR_EVENT_HEADER val = { 0, 0, {0}, 0 };
                std::memcpy(&val, ptr, sizeof(TCG_PCR_EVENT_HEADER));
                return val;
            };

            if (log_data.size() < sizeof(TCG_PCR_EVENT_HEADER)) {
                return false;
            }

            const u8* p_buffer = log_data.data();
            const size_t total_size = log_data.size();

            /* Validate Spec ID Event header (legacy format) */
            const TCG_PCR_EVENT_HEADER first_hdr = read_hdr(p_buffer);
            if (first_hdr.pcrIndex != 0 || first_hdr.eventType != 0x00000003 /* EV_NO_ACTION */) {
                return false;
            }

            const size_t first_event_data_offset = sizeof(TCG_PCR_EVENT_HEADER);
            if (total_size < first_event_data_offset + first_hdr.eventSize) {
                return false;
            }

            const u8* spec_id_payload = p_buffer + first_event_data_offset;
            const u32 spec_id_size = first_hdr.eventSize;

            if (spec_id_size < 28 || std::memcmp(spec_id_payload, "Spec ID Event03", 15) != 0) {
                return false;
            }

            const u32 num_algs = read_u32(spec_id_payload + 24);

            if (num_algs > 16 || spec_id_size < 28 + (num_algs * sizeof(alg_size))) {
                return false;
            }

            std::vector<alg_size> active_algs(num_algs);
            const u8* alg_ptr = spec_id_payload + 28;
            for (u32 i = 0; i < num_algs; ++i) {
                active_algs[i] = read_alg_size(alg_ptr + (i * sizeof(alg_size)));
            }

            auto get_digest_size = [&active_algs](const u16 algorithm_id) noexcept -> u16 {
                for (const auto& alg : active_algs) {
                    if (alg.algId == algorithm_id) {
                        return alg.digestSize;
                    }
                }
                switch (algorithm_id) {
                    case 0x0004: return 20; /* SHA-1 */
                    case 0x000B: return 32; /* SHA-256 */
                    case 0x000C: return 48; /* SHA-384 */
                    case 0x000D: return 64; /* SHA-512 */
                    default:     return 0;
                }
            };

            /* Move pointer to sequential crypto-agile TCG_PCR_EVENT2 items */
            size_t current_offset = first_event_data_offset + spec_id_size;

            while (current_offset < total_size) {
                if (total_size - current_offset < 12) {
                    break;
                }

                const u8* event_ptr = p_buffer + current_offset;
                VMAWARE_PREFETCH(event_ptr + 128, _MM_HINT_T0);

                const u32 pcr_index = read_u32(event_ptr);
                const u32 event_type = read_u32(event_ptr + 4);
                const u32 digest_count = read_u32(event_ptr + 8);

                size_t local_offset = 12;

                bool parse_error = false;
                for (u32 i = 0; i < digest_count; ++i) {
                    const size_t remaining_space = total_size - current_offset;

                    if (local_offset > remaining_space || remaining_space - local_offset < 2) {
                        parse_error = true;
                        break;
                    }
                    const u16 algorithm_id = read_u16(event_ptr + local_offset);
                    local_offset += 2;

                    const u16 digest_size = get_digest_size(algorithm_id);
                    if (digest_size == 0) {
                        parse_error = true;
                        break;
                    }

                    if (total_size - current_offset - local_offset < digest_size) {
                        parse_error = true;
                        break;
                    }
                    local_offset += digest_size;
                }

                if (parse_error) {
                    break;
                }

                if (total_size - current_offset - local_offset < 4) {
                    break;
                }
                const u32 event_size = read_u32(event_ptr + local_offset);
                local_offset += 4;

                if (total_size - current_offset - local_offset < event_size) {
                    break;
                }

                const u8* payload = event_ptr + local_offset;

                if (pcr_index == 0 && event_type == 0x80000008) {
                    if (event_size >= 16) {
                        const u64 base_addr = read_u64(payload);
                        const u64 blob_len = read_u64(payload + 8);

                        /* OVMF's memory bounds of the SEC and PEI execution phases */
                        if ((base_addr == 0x830000 && blob_len == 0xD0000) ||
                            (base_addr == 0x900000 && blob_len == 0xE80000)) {
                            return true;
                        }
                    }
                }

                current_offset += local_offset + event_size;
            }

            return false;
        };

        const HMODULE tbs = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (tbs == nullptr) {
            return false;
        }

        constexpr const char* function_names[] = {
            "Tbsi_Get_TCG_Log_Ex",
            "Tbsi_Context_Create",
            "Tbsip_Context_Close",
            "Tbsi_Get_TCG_Log"
        };
        void* functions[ARRAYSIZE(function_names)] = {};

        memory::get_function(tbs, function_names, functions, ARRAYSIZE(function_names), false);

        tbsi_get_tcg_log_ex_fn tbsi_get_tcg_log_ex = reinterpret_cast<tbsi_get_tcg_log_ex_fn>(functions[0]);
        tbsi_context_create_fn tbsi_context_create = reinterpret_cast<tbsi_context_create_fn>(functions[1]);
        tbsip_context_close_fn tbsip_context_close = reinterpret_cast<tbsip_context_close_fn>(functions[2]);
        tbsi_get_tcg_log_fn    tbsi_get_tcg_log = reinterpret_cast<tbsi_get_tcg_log_fn>(functions[3]);

        bool vm_detected = false;

        if (tbsi_get_tcg_log_ex) {
            for (UINT32 log_type : { 0, 2 }) {
                UINT32 log_size = 0;
                TBS_RESULT res = tbsi_get_tcg_log_ex(log_type, nullptr, &log_size);
                if ((res == 0 || res == static_cast<TBS_RESULT>(TBS_E_INSUFFICIENT_BUFFER)) && log_size > 0) {
                    std::vector<u8> buffer(log_size);
                    if (tbsi_get_tcg_log_ex(log_type, buffer.data(), &log_size) == 0) {
                        buffer.resize(log_size);
                        if (parse_log(buffer)) {
                            vm_detected = true;
                            break;
                        }
                    }
                }
            }
        }
        else if (tbsi_context_create && tbsip_context_close && tbsi_get_tcg_log) {
            VMAWARE_TBS_CONTEXT_PARAMS params{ 1 };
            TBS_HCONTEXT context_handle = nullptr;
            if (tbsi_context_create(&params, &context_handle) == 0) {
                UINT32 log_size = 0;
                TBS_RESULT res = tbsi_get_tcg_log(context_handle, nullptr, &log_size);
                if ((res == 0 || res == static_cast<TBS_RESULT>(TBS_E_INSUFFICIENT_BUFFER)) && log_size > 0) {
                    std::vector<u8> buffer(log_size);
                    if (tbsi_get_tcg_log(context_handle, buffer.data(), &log_size) == 0) {
                        buffer.resize(log_size);
                        if (parse_log(buffer)) {
                            vm_detected = true;
                        }
                    }
                }
                tbsip_context_close(context_handle);
            }
        }

        FreeLibrary(tbs);
        return vm_detected;
    }


    /**
     * @brief Check whether a TPM is virtual or has been passed through to a VM
     * @category Windows
     * @implements VM::TPM
     */
    [[nodiscard]] static bool tpm() {
    #pragma pack(push, 1)
        struct tcg_pcr_event_header {
            u32 pcr_index;
            u32 event_type;
            u8 digest[20];
            u32 event_size;
        };
    #pragma pack(pop)

        struct tracked_event {
            u32 event_type;
            u8 digest[32];
            u32 digest_size;
        };

        struct tracked_event_list {
            tracked_event* items = nullptr;
            u32 count = 0;
            u32 capacity = 0;

            bool push(const tracked_event& ev) noexcept {
                if (count == capacity) {
                    const u32 new_cap = capacity ? capacity * 2 : 16;
                    tracked_event* const new_items = static_cast<tracked_event*>(realloc(items, new_cap * sizeof(tracked_event)));
                    if (!new_items) {
                        return false;
                    }
                    items = new_items;
                    capacity = new_cap;
                }
                items[count++] = ev;
                return true;
            }

            void free_list() noexcept {
                if (items) {
                    free(items);
                    items = nullptr;
                }
                count = 0;
                capacity = 0;
            }
        };

        struct alg_size_pair {
            u16 alg_id;
            u16 digest_size;
        };

        struct alg_size_map {
            alg_size_pair pairs[16] = {};
            u32 count = 0;

            void set(const u16 alg_id, const u16 digest_size) noexcept {
                for (u32 i = 0; i < count; i++) {
                    if (pairs[i].alg_id == alg_id) {
                        pairs[i].digest_size = digest_size;
                        return;
                    }
                }
                if (count < 16) {
                    pairs[count].alg_id = alg_id;
                    pairs[count].digest_size = digest_size;
                    count++;
                }
            }

            u16 get(const u16 alg_id, bool* const found) const noexcept {
                for (u32 i = 0; i < count; i++) {
                    if (pairs[i].alg_id == alg_id) {
                        if (found) {
                            *found = true;
                        }
                        return pairs[i].digest_size;
                    }
                }
                if (found) {
                    *found = false;
                }
                return 0;
            }
        };

        struct tbs_context_params_2 {
            u32 version;
            u32 as_uint32;
        };

        using TBS_HCONTEXT = void*;
        using TBS_RESULT = unsigned long;

        using tbsi_context_create_t = TBS_RESULT(__stdcall*)(const void*, TBS_HCONTEXT*);
        using tbsi_get_tcg_log_ex_t = TBS_RESULT(__stdcall*)(u32, u8*, u32*);
        using tbsip_submit_command_t = TBS_RESULT(__stdcall*)(TBS_HCONTEXT, u32, u32, const u8*, u32, u8*, u32*);
        using tbsip_context_close_t = TBS_RESULT(__stdcall*)(TBS_HCONTEXT);

        static const char* default_algorithms_profile =
            "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
            "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
            "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
            "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,"
            "ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,"
            "ctr,ofb,cbc,cfb,ecb";

        auto read_u16 = [](const u8* const ptr) noexcept -> u16 {
            u16 val;
            std::memcpy(&val, ptr, sizeof(val));
            return val;
        };

        auto read_u32 = [](const u8* const ptr) noexcept -> u32 {
            u32 val;
            std::memcpy(&val, ptr, sizeof(val));
            return val;
        };

        using bcrypt_open_algorithm_provider_t = NTSTATUS(__stdcall*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
        using bcrypt_get_property_t = NTSTATUS(__stdcall*)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
        using bcrypt_create_hash_t = NTSTATUS(__stdcall*)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
        using bcrypt_hash_data_t = NTSTATUS(__stdcall*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using bcrypt_finish_hash_t = NTSTATUS(__stdcall*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        using bcrypt_destroy_hash_t = NTSTATUS(__stdcall*)(BCRYPT_HASH_HANDLE);
        using bcrypt_close_algorithm_provider_t = NTSTATUS(__stdcall*)(BCRYPT_ALG_HANDLE, ULONG);

        bcrypt_open_algorithm_provider_t p_bcrypt_open_algorithm_provider = nullptr;
        bcrypt_get_property_t p_bcrypt_get_property = nullptr;
        bcrypt_create_hash_t p_bcrypt_create_hash = nullptr;
        bcrypt_hash_data_t p_bcrypt_hash_data = nullptr;
        bcrypt_finish_hash_t p_bcrypt_finish_hash = nullptr;
        bcrypt_destroy_hash_t p_bcrypt_destroy_hash = nullptr;
        bcrypt_close_algorithm_provider_t p_bcrypt_close_algorithm_provider = nullptr;

        tbsi_context_create_t p_tbsi_context_create = nullptr;
        tbsi_get_tcg_log_ex_t p_tbsi_get_tcg_log_ex = nullptr;
        tbsip_submit_command_t p_tbsip_submit_command = nullptr;
        tbsip_context_close_t p_tbsip_context_close = nullptr;

        HMODULE bcrypt_dll = nullptr;
        HMODULE tbs_dll = nullptr;
        TBS_HCONTEXT h_tbs_context = nullptr;
        u8* log_buffer = nullptr;
        BCRYPT_ALG_HANDLE h_bcrypt_alg = nullptr;
        u8* hash_object_buffer = nullptr;
        DWORD cb_hash_object = 0;
        tracked_event_list pcr_events[24] = {};
        bool passthrough_detected = false;

        auto free_resources = [&]() noexcept {
            for (u32 i = 0; i < 24; ++i) {
                pcr_events[i].free_list();
            }
            if (log_buffer) {
                free(log_buffer);
                log_buffer = nullptr;
            }
            if (hash_object_buffer) {
                free(hash_object_buffer);
                hash_object_buffer = nullptr;
            }
            if (h_bcrypt_alg) {
                if (p_bcrypt_close_algorithm_provider) {
                    p_bcrypt_close_algorithm_provider(h_bcrypt_alg, 0);
                }
                h_bcrypt_alg = nullptr;
            }
            if (h_tbs_context && p_tbsip_context_close) {
                p_tbsip_context_close(h_tbs_context);
                h_tbs_context = nullptr;
            }
            if (tbs_dll) {
                FreeLibrary(tbs_dll);
                tbs_dll = nullptr;
            }
            if (bcrypt_dll) {
                FreeLibrary(bcrypt_dll);
                bcrypt_dll = nullptr;
            }
        };

        bcrypt_dll = LoadLibraryExW(L"bcrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!bcrypt_dll) {
            return false;
        }

        const char* bcrypt_names[] = {
            "BCryptOpenAlgorithmProvider",
            "BCryptGetProperty",
            "BCryptCreateHash",
            "BCryptHashData",
            "BCryptFinishHash",
            "BCryptDestroyHash",
            "BCryptCloseAlgorithmProvider"
        };
        void* bcrypt_funcs[7] = { nullptr };
        memory::get_function(bcrypt_dll, bcrypt_names, bcrypt_funcs, 7, false);

        p_bcrypt_open_algorithm_provider = reinterpret_cast<bcrypt_open_algorithm_provider_t>(bcrypt_funcs[0]);
        p_bcrypt_get_property = reinterpret_cast<bcrypt_get_property_t>(bcrypt_funcs[1]);
        p_bcrypt_create_hash = reinterpret_cast<bcrypt_create_hash_t>(bcrypt_funcs[2]);
        p_bcrypt_hash_data = reinterpret_cast<bcrypt_hash_data_t>(bcrypt_funcs[3]);
        p_bcrypt_finish_hash = reinterpret_cast<bcrypt_finish_hash_t>(bcrypt_funcs[4]);
        p_bcrypt_destroy_hash = reinterpret_cast<bcrypt_destroy_hash_t>(bcrypt_funcs[5]);
        p_bcrypt_close_algorithm_provider = reinterpret_cast<bcrypt_close_algorithm_provider_t>(bcrypt_funcs[6]);

        if (!p_bcrypt_open_algorithm_provider || !p_bcrypt_get_property || !p_bcrypt_create_hash ||
            !p_bcrypt_hash_data || !p_bcrypt_finish_hash || !p_bcrypt_destroy_hash || !p_bcrypt_close_algorithm_provider) {
            free_resources();
            return false;
        }

        NTSTATUS b_status = p_bcrypt_open_algorithm_provider(&h_bcrypt_alg, L"SHA256", nullptr, 0);
        if (b_status != 0) {
            free_resources();
            return false;
        }

        DWORD cb_data = sizeof(DWORD);
        b_status = p_bcrypt_get_property(h_bcrypt_alg, L"ObjectLength", reinterpret_cast<PBYTE>(&cb_hash_object), cb_data, &cb_data, 0);
        if (b_status != 0 || cb_hash_object == 0) {
            free_resources();
            return false;
        }

        hash_object_buffer = static_cast<u8*>(malloc(cb_hash_object));
        if (!hash_object_buffer) {
            free_resources();
            return false;
        }

        tbs_dll = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!tbs_dll) {
            free_resources();
            return false;
        }

        const char* tbs_names[] = {
            "Tbsi_Context_Create",
            "Tbsi_Get_TCG_Log_Ex",
            "Tbsip_Submit_Command",
            "Tbsip_Context_Close"
        };
        void* tbs_funcs[4] = { nullptr };
        memory::get_function(tbs_dll, tbs_names, tbs_funcs, 4, false);

        p_tbsi_context_create = reinterpret_cast<tbsi_context_create_t>(tbs_funcs[0]);
        p_tbsi_get_tcg_log_ex = reinterpret_cast<tbsi_get_tcg_log_ex_t>(tbs_funcs[1]);
        p_tbsip_submit_command = reinterpret_cast<tbsip_submit_command_t>(tbs_funcs[2]);
        p_tbsip_context_close = reinterpret_cast<tbsip_context_close_t>(tbs_funcs[3]);

        if (!p_tbsi_context_create || !p_tbsi_get_tcg_log_ex || !p_tbsip_submit_command || !p_tbsip_context_close) {
            free_resources();
            return false;
        }

        auto calculate_sha256 = [&](const u8* const VMAWARE_RESTRICT data, const u32 size, u8* const VMAWARE_RESTRICT out_digest) noexcept -> bool {
            BCRYPT_HASH_HANDLE h_hash = nullptr;
            NTSTATUS status = p_bcrypt_create_hash(h_bcrypt_alg, &h_hash, hash_object_buffer, cb_hash_object, nullptr, 0, 0);
            if (status != 0) {
                return false;
            }

            status = p_bcrypt_hash_data(h_hash, const_cast<PUCHAR>(data), size, 0);
            if (status == 0) {
                status = p_bcrypt_finish_hash(h_hash, out_digest, 32, 0);
            }

            p_bcrypt_destroy_hash(h_hash);
            return (status == 0);
        };

        auto read_tpm_pcr = [&](const TBS_HCONTEXT h_context, const u32 pcr_index, const u16 alg_id, u8* const VMAWARE_RESTRICT out_digest, u32* const VMAWARE_RESTRICT out_digest_size) noexcept -> bool {
            if (pcr_index >= 24) {
                return false;
            }

            u8 cmd[20] = { 0 };
            cmd[0] = 0x80; cmd[1] = 0x01;
            cmd[2] = 0x00; cmd[3] = 0x00; cmd[4] = 0x00; cmd[5] = 0x14;
            cmd[6] = 0x00; cmd[7] = 0x00; cmd[8] = 0x01; cmd[9] = 0x7E;
            cmd[10] = 0x00; cmd[11] = 0x00; cmd[12] = 0x00; cmd[13] = 0x01;

            cmd[14] = static_cast<u8>((alg_id >> 8) & 0xFF);
            cmd[15] = static_cast<u8>(alg_id & 0xFF);
            cmd[16] = 0x03;
            cmd[17] = 0x00;
            cmd[18] = 0x00;
            cmd[19] = 0x00;
            cmd[17 + (pcr_index / 8)] = static_cast<u8>(1 << (pcr_index % 8));

            u8 resp[256] = { 0 };
            u32 resp_size = sizeof(resp);

            const TBS_RESULT hr = p_tbsip_submit_command(h_context, 0, 200, cmd, sizeof(cmd), resp, &resp_size);
            if (hr != 0) {
                return false;
            }

            if (resp_size < 10) {
                return false;
            }
            const u32 code = 
                (static_cast<u32>(resp[6]) << 24) |
                (static_cast<u32>(resp[7]) << 16) |
                (static_cast<u32>(resp[8]) << 8) |
                resp[9];

            if (code != 0) {
                return false;
            }

            u32 offset = 14;

            if (offset + 4 > resp_size) {
                return false;
            }
            const u32 sel_count = 
                (static_cast<u32>(resp[offset]) << 24) |
                (static_cast<u32>(resp[offset + 1]) << 16) |
                (static_cast<u32>(resp[offset + 2]) << 8) |
                resp[offset + 3];

            offset += 4;
            if (sel_count != 1) {
                return false;
            }

            offset += 2;
            if (offset + 1 > resp_size) {
                return false;
            }
            const u8 ret_sizeof_select = resp[offset];
            offset += 1 + ret_sizeof_select;

            if (offset + 4 > resp_size) { 
                return false;
            }
            const u32 digest_count = 
                (static_cast<u32>(resp[offset]) << 24) |
                (static_cast<u32>(resp[offset + 1]) << 16) |
                (static_cast<u32>(resp[offset + 2]) << 8) |
                resp[offset + 3];

            offset += 4;
            if (digest_count != 1) {
                return false;
            }

            if (offset + 2 > resp_size) { 
                return false;
            }
            const u16 digest_size = static_cast<u16>((resp[offset] << 8) | resp[offset + 1]);
            offset += 2;

            if (offset + digest_size > resp_size) {
                return false;
            }

            if (out_digest) {
                std::memcpy(out_digest, resp + offset, digest_size > 32 ? 32 : digest_size);
            }
            if (out_digest_size) {
                *out_digest_size = digest_size;
            }

            return true;
        };

        /* Establish context */
        const tbs_context_params_2 params = { 2, 5 };

        const TBS_RESULT hr = p_tbsi_context_create(&params, &h_tbs_context);
        if (hr != 0) {
            free_resources();
            return false;
        }

        /* Analyze TPM algorithms */
        struct alg_name_id {
            const char* name;
            u16 id;
        };

        static const alg_name_id alg_map[] = {
            {"rsa", 0x0001}, {"tdes", 0x0003}, {"sha1", 0x0004}, {"hmac", 0x0005},
            {"aes", 0x0006}, {"mgf1", 0x0007}, {"keyedhash", 0x0008}, {"xor", 0x000A},
            {"sha256", 0x000B}, {"sha384", 0x000C}, {"sha512", 0x000D}, {"null", 0x0010},
            {"rsassa", 0x0014}, {"rsaes", 0x0015}, {"rsapss", 0x0016}, {"oaep", 0x0017},
            {"ecdsa", 0x0018}, {"ecdh", 0x0019}, {"ecdaa", 0x001A}, {"sm2", 0x001B},
            {"ecschnorr", 0x001C}, {"ecmqv", 0x001D}, {"kdf1-sp800-56a", 0x0020},
            {"kdf2", 0x0021}, {"kdf1-sp800-108", 0x0022}, {"ecc", 0x0023},
            {"symcipher", 0x0025}, {"camellia", 0x0026}, {"cmac", 0x003F},
            {"ctr", 0x0040}, {"ofb", 0x0041}, {"cbc", 0x0042}, {"cfb", 0x0043},
            {"ecb", 0x0044}
        };

        auto name_to_alg = [](const std::string& s, u16* out) noexcept -> bool {
            for (u32 i = 0; i < sizeof(alg_map) / sizeof(alg_map[0]); ++i) {
                if (s == alg_map[i].name) {
                    *out = alg_map[i].id;
                    return true;
                }
            }

            return false;
        };

        auto has_id = [](const u16* list, u32 count, u16 id) noexcept -> bool {
            for (u32 i = 0; i < count; ++i) {
                if (list[i] == id) {
                    return true;
                }
            }

            return false;
        };

        auto add_id = [&](u16* list, u32& count, u16 id) noexcept -> bool {
            if (has_id(list, count, id)) {
                return true;
            }
            if (count >= 64) {
                return false;
            }
            list[count++] = id;
            return true;
        };

        u16 expected_algos[64] = {};
        u32 expected_alg_count = 0;
        u16 actual_algos[64] = {};
        u32 actual_alg_count = 0;

        std::stringstream ss(default_algorithms_profile);
        std::string t;

        while (std::getline(ss, t, ',')) {
            string::trim_inplace(t);
            if (t.empty() || t.find('=') != std::string::npos) {
                continue;
            }

            if (t == "ecc-nist" || t == "ecc-bn" || t == "ecc-sm2-p256" ||
                t == "ctr" || t == "ofb" || t == "cbc" || t == "cfb" || t == "ecb") {
                continue;
            }

            u16 id = 0;
            if (!name_to_alg(t, &id) || !add_id(expected_algos, expected_alg_count, id)) {
                free_resources();
                return false;
            }
        }       

        auto be16 = [](const u8* p) -> u16 {
            return static_cast<u16>((static_cast<u16>(p[0]) << 8) | p[1]);
        };

        auto be32 = [](const u8* p) -> u32 {
            return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) | (static_cast<u32>(p[2]) << 8) | static_cast<u32>(p[3]);
        };

        u8 cmd_alg[22] = {
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x16,
            0x00, 0x00, 0x01, 0x7A,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF
        };

        u8 rsp_alg[4096] = {};
        u32 rsp_alg_size = sizeof(rsp_alg);

        const TBS_RESULT hr_alg = p_tbsip_submit_command(h_tbs_context, 0, 200, cmd_alg, sizeof(cmd_alg), rsp_alg, &rsp_alg_size);

        if (hr_alg != 0 || rsp_alg_size < 19) {
            free_resources();
            return false;
        }

        const u32 alg_rc = be32(rsp_alg + 6);
        const u8 alg_more = rsp_alg[10];
        const u32 alg_cap = be32(rsp_alg + 11);
        const u32 alg_count = be32(rsp_alg + 15);

        if (alg_rc != 0 || alg_more != 0 || alg_cap != 0x00000000) {
            free_resources();
            return false;
        }

        u32 off = 19;
        for (u32 i = 0; i < alg_count; ++i) {
            if (off + 6 > rsp_alg_size) {
                free_resources();
                return false;
            }

            const u16 alg_id = be16(rsp_alg + off);
            off += 6;

            if (!add_id(actual_algos, actual_alg_count, alg_id)) {
                free_resources();
                return false;
            }
        }

        bool alg_mismatch = (expected_alg_count != actual_alg_count);

        for (u32 i = 0; !alg_mismatch && i < expected_alg_count; ++i) {
            if (!has_id(actual_algos, actual_alg_count, expected_algos[i])) {
                alg_mismatch = true;
            }
        }

        for (u32 i = 0; !alg_mismatch && i < actual_alg_count; ++i) {
            if (!has_id(expected_algos, expected_alg_count, actual_algos[i])) {
                alg_mismatch = true;
            }
        }

        if (!alg_mismatch) {
            vma_debug("TPM: libtpm detected");
            free_resources();
            return true;
        }

        const char* manufacturer = nullptr;
        const char* model = nullptr;

        if (util::get_manufacturer_model(&manufacturer, &model)) {
            const bool is_lenovo = string::contains_ci(manufacturer, "LENOVO");
            const bool is_hp = string::contains_ci(manufacturer, "HP") || string::contains_ci(manufacturer, "Hewlett-Packard");
            const bool is_acer = string::contains_ci(manufacturer, "Acer");

            if (is_lenovo || is_hp || is_acer) {
                vma_debug("TPM: Recognized OEM manufacturer which normally manufactures buggy firmware, skipping PCR mismatch check.");
                free_resources();
                return false;
            }
        }

        /* Get raw log size and allocate log buffer */
        u32 log_size = 0;
        const TBS_RESULT hr_log_sz = p_tbsi_get_tcg_log_ex(0, nullptr, &log_size);
        if (hr_log_sz != 0x80284005 && hr_log_sz != 0) {
            free_resources();
            return false;
        }

        log_buffer = static_cast<u8*>(malloc(log_size));
        if (!log_buffer) {
            free_resources();
            return false;
        }

        const TBS_RESULT hr_log_rd = p_tbsi_get_tcg_log_ex(0, log_buffer, &log_size);
        if (hr_log_rd != 0) {
            free_resources();
            return false;
        }

        /* Trace algorithm layouts and map indices */
        alg_size_map alg_to_size;
        alg_to_size.set(0x0004, 20);
        alg_to_size.set(0x000B, 32);

        size_t offset = 0;

        bool header_parsed = false;
        if (offset + sizeof(tcg_pcr_event_header) <= log_size) {
            const u32 first_event_type = read_u32(log_buffer + offset + 4);
            const u32 first_event_size = read_u32(log_buffer + offset + 28);
            offset += sizeof(tcg_pcr_event_header);

            if (offset + first_event_size <= log_size) {
                const u8* const first_event_data = log_buffer + offset;
                offset += first_event_size;

                if (first_event_type == 0x03 && first_event_size >= 24) {
                    if (std::memcmp(first_event_data, "Spec ID Event03", 15) == 0) {
                        const u8 num_algs = first_event_data[23];
                        u32 alg_offset = 24;
                        bool has_sha256 = false;

                        for (u32 i = 0; i < num_algs; ++i) {
                            if (alg_offset + 4 > first_event_size) {
                                break;
                            }
                            const u16 alg_id = read_u16(first_event_data + alg_offset);
                            const u16 digest_size = read_u16(first_event_data + alg_offset + 2);
                            alg_to_size.set(alg_id, digest_size);

                            if (alg_id == 0x000B && digest_size == 32) {
                                has_sha256 = true;
                            }
                            alg_offset += 4;
                        }

                        if (has_sha256) {
                            header_parsed = true;
                        }
                    }
                }
            }
        }

        if (!header_parsed) {
            free_resources();
            return false;
        }

        /* Process log packets sequentially */
        while (offset < log_size) {
            if (offset + 8 > log_size) {
                free_resources();
                return false;
            }
            const u32 pcr_index = read_u32(log_buffer + offset);
            const u32 event_type = read_u32(log_buffer + offset + 4);
            offset += 8;

            if (offset + 4 > log_size) {
                free_resources();
                return false;
            }
            const u32 digest_count = read_u32(log_buffer + offset);
            offset += 4;

            struct temp_digest {
                u16 alg_id;
                u8 digest[64];
                u32 size;
            };

            temp_digest temp_digests[16]{};
            u32 temp_digest_count = 0;
            bool parse_success = true;
            bool has_sha256 = false;

            for (u32 i = 0; i < digest_count; ++i) {
                if (offset + 2 > log_size) { 
                    parse_success = false;
                    break;
                }
                const u16 alg_id = read_u16(log_buffer + offset);
                offset += 2;

                bool found = false;
                const u16 size = alg_to_size.get(alg_id, &found);
                if (!found || size > 64) {
                    parse_success = false;
                    break;
                }

                if (offset + size > log_size) { 
                    parse_success = false; 
                    break;
                }

                if (alg_id == 0x000B) {
                    has_sha256 = true;
                }
                
                if (temp_digest_count < 16) {
                    temp_digests[temp_digest_count].alg_id = alg_id;
                    temp_digests[temp_digest_count].size = size;
                    std::memcpy(temp_digests[temp_digest_count].digest, log_buffer + offset, size);
                    temp_digest_count++;
                }
                offset += size;
            }

            if (!parse_success || !has_sha256) {
                free_resources();
                return false;
            }

            if (offset + 4 > log_size) {
                free_resources();
                return false;
            }

            const u32 event_size = read_u32(log_buffer + offset);
            offset += 4;

            if (offset + event_size > log_size) {
                free_resources();
                return false;
            }
            offset += event_size;

            for (u32 i = 0; i < temp_digest_count; ++i) {
                if (temp_digests[i].alg_id == 0x000B && pcr_index < 24) { /* tpm_alg_sha256 */
                    tracked_event ev{};
                    ev.event_type = event_type;
                    ev.digest_size = temp_digests[i].size;
                    std::memcpy(ev.digest, temp_digests[i].digest, temp_digests[i].size > 32 ? 32 : temp_digests[i].size);
                    if (!pcr_events[pcr_index].push(ev)) {
                        free_resources();
                        return false;
                    }
                }
            }
        }

        /* Perform step-by-step state reconstruction */
        u8 reconstructed_pcrs[24][32];
        std::memset(reconstructed_pcrs, 0, sizeof(reconstructed_pcrs));

        for (u32 pcr_idx = 0; pcr_idx < 8; ++pcr_idx) {
            u8 current_pcr[32] = { 0 };
            for (u32 j = 0; j < pcr_events[pcr_idx].count; ++j) {
                const auto& ev = pcr_events[pcr_idx].items[j];
                if (ev.event_type == 0x00000003) {
                    continue;
                }
                u8 concat[64];
                std::memcpy(concat, current_pcr, 32);
                std::memcpy(concat + 32, ev.digest, 32);
                if (!calculate_sha256(concat, 64, current_pcr)) {
                    free_resources();
                    return false;
                }
            }
            std::memcpy(reconstructed_pcrs[pcr_idx], current_pcr, 32);
        }

        /* Compare logs with active system registers */
        for (u32 pcr_idx = 0; pcr_idx < 8; ++pcr_idx) {
            u8 actual_pcr[32] = { 0 };
            u32 actual_pcr_size = 0;
            if (read_tpm_pcr(h_tbs_context, pcr_idx, 0x000B, actual_pcr, &actual_pcr_size)) {
                if (actual_pcr_size != 32 || std::memcmp(actual_pcr, reconstructed_pcrs[pcr_idx], 32) != 0) {
                    if (pcr_idx != 0 && pcr_idx != 6) {
                        vma_debug("TPM: Detected mismatch on hardware PCR ", pcr_idx);
                        passthrough_detected = true;
                    }
                }
            }
        }

        free_resources();
        return passthrough_detected;
    }


    /*
     * ADD NEW TECHNIQUE FUNCTION HERE
     */
    #if (VMAWARE_CLANG)
        #pragma clang diagnostic pop
    #endif
#endif

#if (VMAWARE_MSVC)
    #pragma endregion
#endif

    /* ============================================================================================== *
     *                                                                                                *                                                                                               *
     *                                        CORE SECTION                                            *
     *                                                                                                *
     * ============================================================================================== */
    struct core {
        struct technique {
            u8 points = 0;                /* this is the certainty score between 0 and 100 */
            bool(*run)();                 /* this is the technique function itself */

            constexpr technique() : run(nullptr) {}
            constexpr technique(u8 points, bool(*run)()) : points(points), run(run) {}
        };

        struct custom_technique { /* for custom techniques the user can implement */
            u8 points;
            u16 id;
            bool(*run)();
        };

        /* Entry for the initialization list */
        struct technique_entry { 
            enum_flags id;
            technique tech;
        };

        /* Entry for brand scoreboard */
        struct brand_entry {
            brand_enum name;
            brand_score_t score;
        };

        /*
         * The actual table, which is derived from the list above and will be
         * used for most functionalities related to technique interactions
         */
        static std::array<technique, enum_size + 1> technique_table;

        static std::vector<VM::core::custom_technique> custom_table; /* users should not have a limit of how many functions they should add, this is the only exception of a heap-allocated object in our core */
        static size_t custom_table_size;

        static std::array<brand_entry, MAX_BRANDS> brand_scoreboard;

        /* Temporary storage to capture which brand was detected by the currently running technique. */
        static brand_enum last_detected_brand;
        static u8 last_detected_score;

        /* 1. One brand, custom score */
        static bool add(const brand_enum p_brand, const u8 score) noexcept {
            return add_score(p_brand, brand_enum::NULL_BRAND, score);
        }

        /* 2. One brand, default score */
        static bool add(const brand_enum p_brand) noexcept {
            return add_score(p_brand, brand_enum::NULL_BRAND, 0);
        }

        /* 3. Two brands, default score */
        static bool add(const brand_enum p_brand, const brand_enum extra_brand) noexcept {
            return add_score(p_brand, extra_brand, 0);
        }

        static bool add_score(const brand_enum p_brand, const brand_enum extra_brand, const u8 score) noexcept {
            last_detected_brand = p_brand;
            last_detected_score = score; /* Store for the engine to read */

            constexpr size_t max_brands = sizeof(brand_scoreboard) / sizeof(brand_scoreboard[0]);

            const u8 p_idx = static_cast<u8>(p_brand);
            if (VMAWARE_LIKELY(p_idx < max_brands && p_brand != brand_enum::NULL_BRAND)) {
                brand_scoreboard[p_idx].score++;
            }

            const u8 e_idx = static_cast<u8>(extra_brand);
            if (extra_brand != brand_enum::NULL_BRAND && e_idx < max_brands) {
                brand_scoreboard[e_idx].score++;
            }

            return true;
        }

        /* Assert if the flag is disabled, far better expression than typing std::bitset member functions */
        [[nodiscard]] static constexpr bool is_disabled(const flagset& flags, const u8 flag_bit) noexcept {
            return flag_bit >= flags.size() || !flags.test(flag_bit);
        }

        /* Assert if the flag is enabled */
        [[nodiscard]] static constexpr bool is_enabled(const flagset& flags, const u8 flag_bit) noexcept {
            return flag_bit < flags.size() && flags.test(flag_bit);
        }

        /* Cache technique range mask */
        static flagset get_techniques_mask() noexcept {
            static const flagset mask = []() {
                flagset m;
                for (size_t i = technique_begin; i < technique_end; ++i) {
                    m.set(i);
                }
                return m;
            }();

            return mask;
        }

        /* Cache settings range mask */
        static flagset get_settings_mask() noexcept {
            static const flagset mask = []() {
                flagset m;
                for (size_t i = settings_begin; i < settings_end; ++i) {
                    m.set(i);
                }
                return m;
            }();

            return mask;
        }

        [[nodiscard]] static bool are_techniques_empty(const flagset& flags) noexcept {
            return (flags & get_techniques_mask()).none();
        }

        [[nodiscard]] static bool is_setting_flag_set(const flagset& flags) noexcept {
            return (flags & get_settings_mask()).any();
        }

        /* Run every VM detection mechanism in the technique table */
        static u16 run_all(const flagset& flags, const bool shortcut = false) noexcept {
            u16 points = 0;
            detected_count_num = 0;

            /* Reset scoreboard at the start of a run to prevent score leakage */
            for (size_t i = 0; i < MAX_BRANDS; ++i) {
                brand_scoreboard[i].score = 0;
                brand_scoreboard[i].name = static_cast<brand_enum>(i);
            }

            const u16 threshold_points = core::is_enabled(flags, HIGH_THRESHOLD) ? high_threshold_score : threshold_score;

            const size_t tech_limit = technique_table.size(); /* (enum_size + 1) */
            for (size_t i = technique_begin; i < technique_end; ++i) {
                VMAWARE_ASSUME(i < tech_limit);

                const enum_flags technique_macro = static_cast<enum_flags>(i);
                const technique& technique_data = technique_table[i];

                /* Skip empty entries */
                if (!technique_data.run) {
                    continue;
                }

                /* Check if the technique is disabled */
                if (core::is_disabled(flags, technique_macro)) {
                    continue;
                }

                /* Check if the technique is cached already */
                if (memo::is_cached(technique_macro)) {
                    const memo::data_t data = memo::cache_fetch(technique_macro);

                    if (data.result) {
                        points += data.points;
                        detected_count_num++;

                        if (data.brand_name != brand_enum::NULL_BRAND) {
                            add(data.brand_name);
                        }
                    }

                    continue;
                }

                /* Reset the last detected brand before running */
                last_detected_brand = brand_enum::NULL_BRAND;
                last_detected_score = 0;

                /* Run the technique */
                const bool result = technique_data.run();

                if (result) {
                    /* Determine which points to use: Override or Default */
                    const u8 points_to_add = (last_detected_score > 0) ? last_detected_score : technique_data.points;

                    points += points_to_add;
                    /*
                     * This is specific to VM::detected_count() which
                     * returns the number of techniques that found a VM.
                     */
                    detected_count_num++;

                    /* Retrieve the brand that was set during execution (if any) */
                    const enum brand_enum detected_brand = last_detected_brand;
                    /* Store the current technique result to the cache */
                    memo::cache_store(technique_macro, result, points_to_add, detected_brand);
                }
                else {
                    memo::cache_store(technique_macro, false, 0);
                }

                /*
                 * For things like VM::detect() and VM::percentage(),
                 * a score of 150+ is guaranteed to be a VM, so
                 * there's no point in running the rest of the techniques
                 * (unless the threshold is set to be higher, but it's the
                 * same story here nonetheless, except the threshold is 300)
                 */
                if (shortcut && (points >= threshold_points)) {
                    return points;
                }
            }

            /* For custom VM techniques, won't be used most of the time */
            if (VMAWARE_UNLIKELY(!core::custom_table.empty())) {
                for (const auto& technique : core::custom_table) {
                    /* If cached, return that result */
                    if (memo::is_cached(technique.id)) {
                        const memo::data_t data = memo::cache_fetch(technique.id);

                        if (data.result) {
                            points += data.points;
                            detected_count_num++;
                        }
                        continue;
                    }

                    /* Run the custom technique */
                    const bool result = technique.run();

                    /* Accumulate a few important values */
                    if (result) {
                        points += technique.points;
                        detected_count_num++;
                    }

                    /* Cache the result */
                    memo::cache_store(
                        technique.id,
                        result,
                        technique.points
                    );
                }
            }

            return points;
        }

        static flagset flag_collector;
        static flagset disabled_flag_collector;

        /* Alternative settings method */
        struct settings {
            flagset flag_collector = generate_default();

            VMAWARE_CONSTEXPR void enable(const enum_flags flag) noexcept {
                const auto idx = static_cast<size_t>(flag);
                if (idx < flag_collector.size()) {
                    flag_collector.set(idx, true);
                }
            }

            VMAWARE_CONSTEXPR void disable(const enum_flags flag) noexcept {
                const auto idx = static_cast<size_t>(flag);
                if (idx < flag_collector.size()) {
                    flag_collector.set(idx, false);
                }
            }

            constexpr bool is_set(const enum_flags flag) const noexcept {
                return static_cast<size_t>(flag) < flag_collector.size() && flag_collector.test(static_cast<size_t>(flag));
            }
        };

        static void generate_default(flagset& flags) noexcept {
            static const flagset default_flags = []() {
                flagset f;
                f.set();

                /* Disable all disabled techniques */
                for (const auto id : disabled_techniques) {
                    const auto idx = static_cast<size_t>(id);
                    if (idx < f.size()) {
                        f.reset(idx);
                    }
                }

                /* Disable all the settings flags except for VM::DEFAULT */
                f.reset(EXPERIMENTAL);
                f.reset(HIGH_THRESHOLD);
                f.reset(NULL_ARG);
                f.reset(DYNAMIC);
                f.reset(MULTIPLE);
                f.reset(ALL);

                return f;
            }();

            flags = default_flags;
        }

        static flagset generate_default() noexcept {
            flagset flags;
            generate_default(flags);
            return flags;
        }

        static void generate_all(flagset& flags) noexcept {
            generate_default(flags);

            for (const enum_flags technique : disabled_techniques) {
                const auto idx = static_cast<size_t>(technique);
                if (idx < flags.size()) {
                    flags.set(idx, true);
                }
            }
        }

        static void reset_disabled_flagset() noexcept {
            disabled_flag_collector.reset();
            for (const auto technique : disabled_techniques) {
                const auto idx = static_cast<size_t>(technique);
                if (idx < disabled_flag_collector.size()) {
                    disabled_flag_collector.set(idx, true);
                }
            }
        }

        static void disable_experimental_techniques() noexcept {
            for (const auto technique : experimental_techniques) {
                const auto idx = static_cast<size_t>(technique);
                if (idx < disabled_flag_collector.size()) {
                    disabled_flag_collector.set(idx, true);
                }
            }
        }

        /* SFINAE base case for compile-time validation of zero arguments */
        template <typename... Args>
        static constexpr typename std::enable_if<sizeof...(Args) == 0, bool>::type
            verify_flags() noexcept {
            return true;
        }

        /* Recursive compile-time validation for 1 or more arguments */
        template <typename T, typename... Args>
        static constexpr bool verify_flags() noexcept {
            return std::is_same<typename std::decay<T>::type, enum_flags>::value&& verify_flags<Args...>();
        }

        /* Overload for zero arguments to prevent C4127 constant conditional warning */
        static flagset arg_handler() noexcept {
            flagset collector;
            generate_default(collector);
            return collector;
        }

        /* Overload for 1 or more arguments */
        template <typename T, typename... Args>
        static VMAWARE_CONSTEXPR flagset arg_handler(T first, Args... args) {
            static_assert(verify_flags<T, Args...>(), "argument handler only accepts enum_flags variables");

            flagset collector;
            /* C++11 initializer list expansion trick to loop over the variadic arguments one by one */
            using expander = int[];
            (void)expander {
                0, (collector.set(static_cast<size_t>(first), true), 0), (collector.set(static_cast<size_t>(args), true), 0)...
            };

            if (collector.test(DEFAULT)) {
                generate_default(collector);
            }

            if (are_techniques_empty(collector)) {
                collector |= generate_default();
            }

            if (collector.test(ALL)) {
                generate_all(collector);
            }

            if (collector.test(EXPERIMENTAL)) {
                disable_experimental_techniques();
            }

            collector &= ~disabled_flag_collector;

            return collector;
        }

        /* Same as above but for VM::disable which only accepts technique flags */
        template <typename... Args>
        static void disabled_arg_handler(Args... args) {
            static_assert(verify_flags<Args...>(), "disabled argument handler only accepts enum_flags variables");
            static_assert(sizeof...(Args) > 0, "VM::DISABLE() must contain at least one flag");

            using expander = int[];
            (void)expander {
                0, (disabled_flag_collector.set(static_cast<size_t>(args), true), 0)...
            };

            /* Check if a settings flag is set, which is not valid */
            if (core::is_setting_flag_set(disabled_flag_collector)) {
                throw std::invalid_argument("VM::DISABLE() must not contain a settings flag, they are disabled by default anyway");
            }
        }
    };

// START OF PUBLIC FUNCTIONS

    using settings = core::settings;

    /**
     * @brief Check for a specific technique based on flag argument
     * @param u8 (flags from VM wrapper)
     * @return bool
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmcheck
     */
    static bool check(
        const enum_flags flag_bit
    #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
        , [[maybe_unused]] const std::source_location& loc = std::source_location::current()
    #endif
    ) {
    #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
        VMAWARE_UNUSED(loc);
    #endif
        if (VMAWARE_UNLIKELY(util::is_unsupported(flag_bit))) {
            memo::cache_store(flag_bit, false, 0);
            return false;
        }

        auto throw_error = [&](const char* text) -> void {
            std::string msg = text;
        #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
            msg += ", error in ";
            msg += loc.function_name();
            msg += " at ";
            msg += loc.file_name();
            msg += ":" + std::to_string(loc.line());
        #endif
            msg += ". Consult the documentation's flag handler for VM::check()";
            throw std::invalid_argument(msg);
        };

        if (flag_bit > enum_size) {
            throw_error("Flag argument must be a valid");
        }

        /* Check if the bit is a settings flag, which shouldn't be allowed */
        if (
            (flag_bit == HIGH_THRESHOLD) ||
            (flag_bit == DYNAMIC) ||
            (flag_bit == MULTIPLE)
        ) {
            throw_error("Flag argument must be a technique flag and not a settings flag");
        }

        /* If the technique is already cached, return the cached value instead */
        if (memo::is_cached(flag_bit)) {
            const memo::data_t data = memo::cache_fetch(flag_bit);
            return data.result;
        }

        if (flag_bit >= technique_end) {
            return false;
        }

        /* VMAWARE_ASSUME(flag_bit < core::technique_table.size()); */
        const core::technique& pair = core::technique_table.at(flag_bit);

        if (auto run_fn = pair.run) {
            core::last_detected_brand = brand_enum::NULL_BRAND;
            core::last_detected_score = 0;

            const bool result = run_fn();
            const u8 points_to_add = (core::last_detected_score > 0) ? core::last_detected_score : pair.points;

            if (result) {
                detected_count_num++;
            }

            memo::cache_store(flag_bit, result, result ? points_to_add : 0, core::last_detected_brand);
            return result;
        }

        throw_error("Flag is not known or not implemented");
        return false; /* Useless but avoids compiler warnings */
    }


    /**
     * @brief Fetch the VM brand
     * @param any flag combination in VM structure or nothing (VM::MULTIPLE can be added)
     * @return const char*
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    template <typename ...Args>
    static std::string brand(const Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return brand(flags);
    }


    static std::string brand(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return brand(flags);
    }


    static std::string brand(const flagset& flags = core::generate_default()) {
        /* Is the multiple setting flag enabled? */
        const bool is_multiple = core::is_enabled(flags, MULTIPLE);

        if (is_multiple) {
            return brands::brand_multiple(flags);
        }

        const enum brand_enum b = brands::brand_single(flags);
        return brands::brand_enum_to_string(b);
    }


    /**
     * @brief Detect if running inside a VM
     * @param any flag combination in VM structure or nothing
     * @return bool
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmdetect
     */
    template <typename ...Args>
    static bool detect(const Args ...args) {
        /* Fetch all the flags in a std::bitset */
        const flagset flags = core::arg_handler(args...);
        return detect(flags);
    }


    static bool detect(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return detect(flags);
    }


    static bool detect(const flagset &flags = core::generate_default()) {
        /*
         * Run all the techniques based on the
         * flags above, and get a total score
         */
        const u16 points = core::run_all(flags, SHORTCUT);

        u16 threshold = threshold_score;

        /*
         * If high threshold is set, the bar
         * will be 300. If not, leave it as 150
         */
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        if (points >= threshold) {
            return true;
        }

        return false;
    }


    /**
     * @brief Get the percentage of how likely it's a VM
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmpercentage
     */
    template <typename ...Args>
    static u8 percentage(const Args ...args) {
        /* Fetch all the flags in a std::bitset */
        const flagset flags = core::arg_handler(args...);
        return percentage(flags);
    }


    static u8 percentage(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return percentage(flags);
    }


    static u8 percentage(const flagset &flags = core::generate_default()) {
        /*
         * Run all the techniques based on the
         * flags above, and get a total score
         */
        const u16 points = core::run_all(flags, SHORTCUT);

        u8 percent = 0;
        u16 threshold = threshold_score;

        /* Set to 300 if high threshold is enabled */
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        if (points >= threshold) {
            percent = 100;
        } else if (points >= 100) {
            percent = 99;
        } else {
            percent = static_cast<u8>(std::min<u16>(points, 99));
        }

        return percent;
    }


    /**
     * @brief Add a custom technique to the VM detection technique collection
     * @param either a function pointer, lambda function, or std::function<bool()>
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmaddcustom
     * @return void
     */
    static void add_custom(
        const u8 percent,
        bool(*detection_func)()
        #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
        , const std::source_location& loc = std::source_location::current()
        #endif
    ) {
        #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
            VMAWARE_UNUSED(loc);
        #endif

        auto throw_error = [&](const char* text) -> void {
            std::string msg = text;
        #if (VMAWARE_SOURCE_LOCATION_SUPPORTED)
            msg += ", error in ";
            msg += loc.function_name();
            msg += " at ";
            msg += loc.file_name();
            msg += ":" + std::to_string(loc.line());
        #endif
            msg += ". Consult the documentation's flag handler for VM::add_custom()";
            throw std::invalid_argument(msg);
        };

        if (VMAWARE_UNLIKELY(percent > 100)) {
            throw_error("Percentage parameter must be between 0 and 100");
        }
        /* VMAWARE_ASSUME(percent <= 100); */

        const size_t current_index = core::custom_table.size();

        const core::custom_technique query{
            percent,
            static_cast<u16>(static_cast<int>(base_technique_count) + static_cast<int>(current_index) + 1),
            detection_func
        };

        technique_count++;

        core::custom_table.push_back(query);
    }


    /**
     * @brief disable the provided technique flags so they are not counted to the overall result
     * @param technique flag(s) only
     * @link https://github.com/NotRequiem/VMAware/blob/main/docs/documentation.md#vmdetect
     * @return flagset
     */
    template <typename ...Args>
    static enum_flags DISABLE(const Args ...args) {
        /*
         * Basically core::arg_handler but in reverse,
         * it'll clear the bits of the provided flags
         */
        core::disabled_arg_handler(args...);
        return VM::NULL_ARG;
    }


    /**
     * @brief This will convert the technique flag into a string, which will correspond to the technique name
     * @param single technique flag in VM structure
     */
    [[nodiscard]] static std::string flag_to_string(const enum_flags flag) {
        switch (flag) {
            // START OF TECHNIQUE LIST
            case VMID: return "VMID";
            case CPU_BRAND: return "CPU_BRAND";
            case HYPERVISOR_BIT: return "HYPERVISOR_BIT";
            case HYPERVISOR_STR: return "HYPERVISOR_STR";
            case TIMER: return "TIMER";
            case THREAD_COUNT: return "THREAD_COUNT";
            case MAC: return "MAC";
            case TEMPERATURE: return "TEMPERATURE";
            case SYSTEMD: return "SYSTEMD";
            case CVENDOR: return "CVENDOR";
            case CTYPE: return "CTYPE";
            case DOCKERENV: return "DOCKERENV";
            case DMIDECODE: return "DMIDECODE";
            case DMESG: return "DMESG";
            case HWMON: return "HWMON";
            case DLL: return "DLL";
            case HWMODEL: return "HWMODEL";
            case WINE: return "WINE";
            case POWER_CAPABILITIES: return "POWER_CAPABILITIES";
            case PROCESSES: return "PROCESSES";
            case LINUX_USER_HOST: return "LINUX_USER_HOST";
            case GAMARUE: return "GAMARUE";
            case BOCHS_CPU: return "BOCHS_CPU";
            case MAC_MEMSIZE: return "MAC_MEMSIZE";
            case MAC_IOKIT: return "MAC_IOKIT";
            case IOREG_GREP: return "IOREG_GREP";
            case MAC_SIP: return "MAC_SIP";
            case VPC_INVALID: return "VPC_INVALID";
            case SYSTEM_REGISTERS: return "SYSTEM_REGISTERS";
            case VMWARE_STR: return "VMWARE_STR";
            case MUTEX: return "MUTEX";
            case THREAD_MISMATCH: return "THREAD_MISMATCH";
            case CUCKOO: return "CUCKOO";
            case AZURE: return "AZURE";
            case DISPLAY: return "DISPLAY";
            case BLUESTACKS_FOLDERS: return "BLUESTACKS_FOLDERS";
            case CPUID_SIGNATURE: return "CPUID_SIGNATURE";
            case KGT_SIGNATURE: return "KGT_SIGNATURE";
            case QEMU_VIRTUAL_DMI: return "QEMU_VIRTUAL_DMI";
            case QEMU_USB: return "QEMU_USB";
            case HYPERVISOR_DIR: return "HYPERVISOR_DIR";
            case UML_CPU: return "UML_CPU";
            case KMSG: return "KMSG";
            case VBOX_MODULE: return "VBOX_MODULE";
            case SYSINFO_PROC: return "SYSINFO_PROC";
            case DMI_SCAN: return "DMI_SCAN";
            case SMBIOS_VM_BIT: return "SMBIOS_VM_BIT";
            case PODMAN_FILE: return "PODMAN_FILE";
            case WSL_PROC: return "WSL_PROC";
            case DRIVERS: return "DRIVERS";
            case DISK: return "DISK";
            case GPU_CAPABILITIES: return "GPU_CAPABILITIES";
            case HANDLES: return "HANDLES";
            case QEMU_FW_CFG: return "QEMU_FW_CFG";
            case VIRTUAL_PROCESSORS: return "VIRTUAL_PROCESSORS";
            case AMD_SEV_MSR: return "AMD_SEV_MSR";
            case VIRTUAL_REGISTRY: return "VIRTUAL_REGISTRY";
            case FIRMWARE: return "FIRMWARE";
            case FILE_ACCESS_HISTORY: return "FILE_ACCESS_HISTORY";
            case AUDIO: return "AUDIO";
            case CONTAINER_PID: return "CONTAINER_PID";
            case DEVICES: return "DEVICES";
            case ACPI_SIGNATURE: return "ACPI_SIGNATURE";
            case TRAP: return "TRAP";
            case UD: return "UD";
            case INTERRUPT_SHADOW: return "INTERRUPT_SHADOW";
            case DBVM: return "DBVM";
            case BOOT_LOGO: return "BOOT_LOGO";
            case MAC_SYS: return "MAC_SYS";
            case KERNEL_OBJECTS: return "KERNEL_OBJECTS";
            case NVRAM: return "NVRAM";
            case CPU_HEURISTIC: return "CPU_HEURISTIC";
            case CLOCK: return "CLOCK";
            case MSR: return "MSR";
            case KVM_INTERCEPTION: return "KVM_INTERCEPTION";
            case HYPERVISOR_HOOK: return "HYPERVISOR_HOOK";
            case SINGLE_STEP: return "SINGLE_STEP";
            case EIP_OVERFLOW: return "EIP_OVERFLOW";
            case SVM_EXCEPTIONS: return "SVM_EXCEPTIONS";
            case CGROUP: return "CGROUP";
            case MEASURED_BOOT: return "MEASURED_BOOT";
            case TPM: return "TPM";
            /* END OF TECHNIQUE LIST */
            case DEFAULT: return "DEFAULT"; 
            case ALL: return "ALL"; 
            case NULL_ARG: return "NULL_ARG"; 
            case HIGH_THRESHOLD: return "HIGH_THRESHOLD"; 
            case DYNAMIC: return "DYNAMIC"; 
            case MULTIPLE: return "MULTIPLE"; 
            default: return "Unknown flag";
        }
    }


    /**
     * @brief Fetch all the brands that were detected in a vector
     * @param any flag combination in VM structure or nothing
     * @return VM::enum_vector
     */
    template <typename ...Args>
    static std::vector<enum_flags> detected_enums(const Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return detected_enums(flags);
    }


    static std::vector<enum_flags> detected_enums(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return detected_enums(flags);
    }


    static std::vector<enum_flags> detected_enums(const flagset &flags = core::generate_default()) {
        std::vector<enum_flags> tmp;

        /*
         * This will loop through all the enums in the technique_vector variable,
         * and then checks each of them and outputs the enum that was detected
         */
        for (u8 i = technique_begin; i < technique_end; ++i) {
            const enum_flags technique_enum = static_cast<enum_flags>(i);

            if ((flags.test(technique_enum)) && (check(technique_enum))) {
                tmp.push_back(technique_enum);
            }
        }

        return tmp;
    }


    /**
     * @brief Fetch the total number of detected techniques
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     */
    template <typename ...Args>
    static u8 detected_count(const Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return detected_count(flags);
    }


    static u8 detected_count(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return detected_count(flags);
    }


    static u8 detected_count(const flagset& flags = core::generate_default()) {
        core::run_all(flags); /* run all the techniques, which will set the detected_count variable */
        return detected_count_num;
    }


    /**
     * @brief Fetch the VM type
     * @param any flag combination in VM structure or nothing
     * @return std::string
     */
    template <typename ...Args>
    static std::string type(const Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return type(flags);
    }


    static std::string type(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return type(flags);
    }


    static std::string type(const flagset &flags = core::generate_default()) {
        const brand_list_t& list = brands::brand_list(flags);

        if (core::is_enabled(flags, MULTIPLE)) {
            if (list.size() > 1) {
                return "Unknown";
            }
        }
    
        const enum brand_enum brand = brands::brand_single(list);

        switch (brand) {
            case brand_enum::XEN: return "Hypervisor (Type 1)";
            case brand_enum::VMWARE_ESX: return "Hypervisor (Type 1)";
            case brand_enum::ACRN: return "Hypervisor (Type 1)";
            case brand_enum::QNX: return "Hypervisor (Type 1)";
            case brand_enum::HYPERV: return "Hypervisor (Type 2)"; /* to clarify you're running under a Hyper-V guest VM */
            case brand_enum::AZURE_HYPERV: return "Hypervisor (Type 1)";
            case brand_enum::KVM: return "Hypervisor (Type 1)";
            case brand_enum::KVM_HYPERV: return "Hypervisor (Type 1)";
            case brand_enum::QEMU_KVM_HYPERV: return "Hypervisor (Type 1)";
            case brand_enum::QEMU_KVM: return "Hypervisor (Type 1)";
            case brand_enum::INTEL_KGT: return "Hypervisor (Type 1)";
            case brand_enum::SIMPLEVISOR: return "Hypervisor (Type 1)";
            case brand_enum::OPENSTACK: return "Hypervisor (Type 1)";
            case brand_enum::KUBEVIRT: return "Hypervisor (Type 1)";
            case brand_enum::POWERVM: return "Hypervisor (Type 1)";
            case brand_enum::AWS_NITRO: return "Hypervisor (Type 1)";
            case brand_enum::LKVM: return "Hypervisor (Type 1)";
            case brand_enum::NOIRVISOR: return "Hypervisor (Type 1)";
            case brand_enum::WSL: return "Hypervisor (Type 1)";  /* Type 1-derived lightweight VM system */
            case brand_enum::DBVM: return "Hypervisor (Type 1)" ;
            case brand_enum::BHYVE: return "Hypervisor (Type 2)";
            case brand_enum::VBOX: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE_EXPRESS: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE_GSX: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE_WORKSTATION: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE_FUSION: return "Hypervisor (Type 2)";
            case brand_enum::PARALLELS: return "Hypervisor (Type 2)";
            case brand_enum::VPC: return "Hypervisor (Type 2)";
            case brand_enum::NVMM: return "Hypervisor (Type 2)";
            case brand_enum::BSD_VMM: return "Hypervisor (Type 2)";
            case brand_enum::HYPERV_VPC: return "Hypervisor (Type 2)";
            case brand_enum::VMWARE_HARD: return "Hypervisor (Type 2)";
            case brand_enum::UTM: return "Hypervisor (Type 2)";
            case brand_enum::INTEL_HAXM: return "Hosted hypervisor / accelerator (Type 2)";
            case brand_enum::CUCKOO: return "Sandbox";
            case brand_enum::SANDBOXIE: return "Sandbox";
            case brand_enum::HYBRID: return "Sandbox";
            case brand_enum::CWSANDBOX: return "Sandbox";
            case brand_enum::JOEBOX: return "Sandbox";
            case brand_enum::ANUBIS: return "Sandbox";
            case brand_enum::COMODO: return "Sandbox";
            case brand_enum::THREATEXPERT: return "Sandbox";
            case brand_enum::QIHOO: return "Sandbox";
            case brand_enum::BOCHS: return "Emulator";
            case brand_enum::BLUESTACKS: return "Emulator";
            case brand_enum::NEKO_PROJECT: return "Emulator";
            case brand_enum::COMPAQ: return "Emulator";
            case brand_enum::INSIGNIA: return "Emulator";
            case brand_enum::CONNECTIX: return "Emulator";
            case brand_enum::QEMU: return "Emulator/Hypervisor (Type 2)";
            case brand_enum::JAILHOUSE: return "Partitioning Hypervisor";
            case brand_enum::UNISYS: return "Partitioning Hypervisor";
            case brand_enum::DOCKER: return "Container";
            case brand_enum::PODMAN: return "Container";
            case brand_enum::OPENVZ: return "Container";
            case brand_enum::CONTAINERD: return "Container";
            case brand_enum::LMHS: return "Hypervisor (unknown type)";
            case brand_enum::WINE: return "Compatibility layer";
            case brand_enum::INTEL_TDX: return "Trusted Domain";
            case brand_enum::APPLE_VZ: return "Unknown";
            case brand_enum::UML: return "Paravirtualised/Hypervisor (Type 2)";
            case brand_enum::AMD_SEV: return "VM encryptor";
            case brand_enum::AMD_SEV_ES: return "VM encryptor";
            case brand_enum::AMD_SEV_SNP: return "VM encryptor";
            case brand_enum::GCE: return "Cloud VM service";
            case brand_enum::BAREVISOR: return "Hypervisor (Type 1)";
            case brand_enum::HYPERPLATFORM: return "Hypervisor (Type 1)";
            case brand_enum::MINIVISOR: return "Hypervisor (Type 1)";
            case brand_enum::HYPERV_ROOT: return "Host machine"; /* This refers to the type 1 hypervisor where Windows normally runs under, we put "Host machine" to clarify you're not running under a traditional VM if this is detected */
            case brand_enum::NULL_BRAND: return "Unknown";
        }

        return "Invalid";
    }


    /**
      * @brief Fetch the conclusion message based on the brand and percentage
      * @param any flag combination in VM structure or nothing
      * @return std::string
      */
    template <typename ...Args>
    static std::string conclusion(const Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return conclusion(flags);
    }


    static std::string conclusion(const settings& settings) {
        const flagset flags = settings.flag_collector;
        return conclusion(flags);
    }


    static std::string conclusion(const flagset& flags = core::generate_default()) {
        if (memo::conclusion::is_cached(flags)) {
            return memo::conclusion::fetch();
        }

        const u8 percent_tmp = percentage(flags);
        
        constexpr const char* very_unlikely = "Very unlikely";
        constexpr const char* unlikely = "Unlikely";
        constexpr const char* potentially = "Potentially";
        constexpr const char* might = "Might be";
        constexpr const char* likely = "Likely";
        constexpr const char* very_likely = "Very likely";
        constexpr const char* inside_vm = "Running inside";
        
        auto make_conclusion = [&](const char* category) -> std::string {
            const brand_list_t& list = brands::brand_list(flags);

            const brand_enum first_brand = brands::brand_single(list);

            const char* addition = " a ";

            /*
             * This basically just fixes the grammatical syntax
             * by either having "a" or "an" before the VM brand
             * name. It would look weird if the conclusion
             * message was "an VirtualBox" or "a Anubis"
             */
            if 
            ( 
                (first_brand == brand_enum::ACRN)        ||
                (first_brand == brand_enum::ANUBIS)      ||
                (first_brand == brand_enum::BSD_VMM)     ||
                (first_brand == brand_enum::INTEL_HAXM)  ||
                (first_brand == brand_enum::APPLE_VZ)    ||
                (first_brand == brand_enum::INTEL_KGT)   ||
                (first_brand == brand_enum::POWERVM)     ||
                (first_brand == brand_enum::OPENSTACK)   ||
                (first_brand == brand_enum::AWS_NITRO)   ||
                (first_brand == brand_enum::OPENVZ)      ||
                (first_brand == brand_enum::INTEL_TDX)   ||
                (first_brand == brand_enum::AMD_SEV)     ||
                (first_brand == brand_enum::AMD_SEV_ES)  ||
                (first_brand == brand_enum::AMD_SEV_SNP) ||
                (first_brand == brand_enum::NULL_BRAND)              
            )   
            {             addition = " an ";             }

            std::string brand_str;

            /*
             * This is basically just to remove the capital "U",
             * since it doesn't make sense to see "an Unknown"
             */
            if (first_brand == brand_enum::NULL_BRAND) {
                brand_str = "unknown";
            } 
            else {
                if (core::is_enabled(flags, MULTIPLE)) {
                    brand_str = brands::brand_multiple(flags);
                } 
                else {
                    brand_str = brands::brand_enum_to_string(first_brand);
                }
            }

            const std::string result = 
                std::string(category) + 
                addition + 
                brand_str + 
                /* Hyper-V artifacts are an exception due to how unique the circumstance is */
                (first_brand == brand_enum::HYPERV_ROOT ? "" : " VM");

            memo::conclusion::store(result.c_str(), flags);

            return result;
        };

        if (core::is_enabled(flags, DYNAMIC)) {
            if (percent_tmp == 0)  { return "Running on bare metal";        }
            if (percent_tmp <= 20) { return make_conclusion(very_unlikely); }
            if (percent_tmp <= 35) { return make_conclusion(unlikely);      }
            if (percent_tmp < 50)  { return make_conclusion(potentially);   }
            if (percent_tmp <= 62) { return make_conclusion(might);         }
            if (percent_tmp <= 75) { return make_conclusion(likely);        }
            if (percent_tmp < 100) { return make_conclusion(very_likely);   }
        }

        if (percent_tmp == 100) {
            return make_conclusion(inside_vm);
        }

        return "Running on bare metal";
    }

    struct vmaware {
        std::string brand;
        std::string type;
        std::string conclusion;
        bool is_vm = false;
        u8 percentage = 0;
        u8 detected_count = 0;
        u16 technique_count = 0;
        std::vector<enum_flags> detected_techniques;
        std::vector<std::string> detected_technique_strings;
        std::vector<enum_flags> disabled_techniques;

        template <typename ...Args>
        vmaware(Args ...args) {
            const flagset flags = core::arg_handler(args...);
            initialise(flags);
        }

        vmaware(const flagset& flags) {
            initialise(flags);
        }

        /* Having this design avoids some niche errors */
        void initialise(const flagset& flags) {
            brand = VM::brand(flags);
            type = VM::type(flags);
            conclusion = VM::conclusion(flags);
            is_vm = VM::detect(flags);
            percentage = VM::percentage(flags);
            detected_count = VM::detected_count(flags);
            technique_count = VM::technique_count;
            detected_techniques = VM::detected_enums(flags);
            detected_technique_strings = [&]() -> std::vector<std::string> {
                std::vector<std::string> tmp{};
                tmp.reserve(detected_techniques.size());

                for (const auto technique : detected_techniques) {
                    tmp.push_back(VM::flag_to_string(technique));
                }

                return tmp;
            }();

            disabled_techniques = VM::disabled_techniques;
        }

    };
};

// ============= EXTERNAL DEFINITIONS =============
/*
 * These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17
 * It's easier to just group them together rather than having C++17<= preprocessors with inline stuff
 */
char VM::memo::conclusion::cache[512] = { 0 };
bool VM::memo::conclusion::cached = false;

/* Scoreboard list of brands, if a VM detection technique detects a brand, that will be incremented here as a single point */
std::array<VM::core::brand_entry, VM::MAX_BRANDS> VM::core::brand_scoreboard = []() {
    std::array<VM::core::brand_entry, VM::MAX_BRANDS> arr{};

    for (u8 i = 0; i < MAX_BRANDS; i++) {
        arr.at(i) = { static_cast<brand_enum>(i), 0 };
    }

    return arr;
}();

static_assert(VM::core::brand_scoreboard.size() == VM::MAX_BRANDS, "brand_scoreboard size must match MAX_BRANDS.");

/* Initial definitions for cache items because C++ forbids in-class initializations */
VM::flagset VM::memo::conclusion::cached_flags{};
VM::flagset VM::memo::single_brand::cached_flags{};
VM::flagset VM::memo::multi_brand::cached_flags{};
VM::flagset VM::memo::brand_list::cached_flags{};
VM::brand_list_t VM::memo::brand_list::cache = {};
VM::hyperx_state VM::memo::hyperx::state = VM::HYPERV_UNKNOWN;
VM::u32 VM::memo::thread_count::thread_count_cache = 0;
std::array<VM::memo::cache_entry, VM::enum_size + 1> VM::memo::cache_table{};
std::array<VM::memo::leaf_entry, VM::memo::leaf_cache::CAPACITY> VM::memo::leaf_cache::table{};
std::string VM::memo::multi_brand::brand_cache;
std::size_t VM::memo::leaf_cache::count = 0;
std::size_t VM::memo::leaf_cache::next_index = 0;
enum VM::brand_enum VM::memo::single_brand::brand_cache = brand_enum::NULL_BRAND;
char VM::memo::cpu_brand::brand_cache[128] = { 0 };
char VM::memo::bios_info::manufacturer[256] = { 0 };
char VM::memo::bios_info::model[128] = { 0 };
bool VM::memo::single_brand::cached = false;
bool VM::memo::multi_brand::cached = false;
bool VM::memo::cpu_brand::cached = false;
bool VM::memo::bios_info::cached = false;
bool VM::memo::hyperx::cached = false;
bool VM::memo::brand_list::cached = false;

enum VM::brand_enum VM::core::last_detected_brand = VM::brand_enum::NULL_BRAND;
VM::u8 VM::core::last_detected_score = 0;

/*
 * These are basically the base values for the core::arg_handler function.
 * It's like a bucket that will collect all the bits enabled. If for example
 * VM::detect(VM::HIGH_THRESHOLD) is passed, the HIGH_THRESHOLD bit will be
 * collected to this flagset (std::bitset) variable, and eventually be provided
 * as the return value for actual end-user functions like VM::detect() to operate on.
 */
VM::flagset VM::core::flag_collector;
VM::flagset VM::core::disabled_flag_collector;

VM::u8 VM::detected_count_num = 0;

std::vector<VM::enum_flags> VM::disabled_techniques = []() {
    std::vector<VM::enum_flags> c;
    return c;
}();

/* This value is incremented each time VM::add_custom is called */
VM::u16 VM::technique_count = VM::base_technique_count;

/* This is initialised as empty, because this is where custom techniques can be added at runtime */
std::vector<VM::core::custom_technique> VM::core::custom_table = {};
size_t VM::core::custom_table_size = 0;

/* The points are debatable, but we think it's fine how it is. Feel free to disagree */
std::array<VM::core::technique, VM::enum_size + 1> VM::core::technique_table = []() {
    std::array<VM::core::technique, VM::enum_size + 1> table{};
    /* FORMAT: { VM::<ID>, { certainty%, function pointer } }, */
    const VM::core::technique_entry entries[] = {
        // START OF TECHNIQUE TABLE
        #if (VMAWARE_WINDOWS)
            {VM::TRAP, {150, VM::trap}},
            {VM::KVM_INTERCEPTION, {150, VM::kvm_interception}},
            {VM::SVM_EXCEPTIONS, {35, VM::svm_exceptions}},
            {VM::MEASURED_BOOT, {150, VM::measured_boot}},
            {VM::INTERRUPT_SHADOW, {150, VM::interrupt_shadow}},
            {VM::EIP_OVERFLOW, {150, VM::eip_overflow}},
            {VM::HYPERVISOR_HOOK, {150, VM::hypervisor_hook}},
            {VM::SINGLE_STEP, {150, VM::single_step}},
            {VM::TPM, {45, VM::tpm}},
            {VM::NVRAM, {100, VM::nvram}},
            {VM::CPU_HEURISTIC, {90, VM::cpu_heuristic}},
            {VM::ACPI_SIGNATURE, {100, VM::acpi_signature}},
            {VM::CLOCK, {45, VM::clock}},
            {VM::POWER_CAPABILITIES, {25, VM::power_capabilities}},
            {VM::GPU_CAPABILITIES, {20, VM::gpu_capabilities}},
            {VM::MSR, {100, VM::msr}},
            {VM::VIRTUAL_PROCESSORS, {100, VM::virtual_processors}},
            {VM::WINE, {150, VM::wine}},
            {VM::DBVM, {150, VM::dbvm}},
            {VM::UD, {100, VM::ud}},
            {VM::DRIVERS, {100, VM::drivers}},
            {VM::HANDLES, {100, VM::device_handles}},
            {VM::KERNEL_OBJECTS, {100, VM::kernel_objects}},
            {VM::DLL, {50, VM::dll}},
            {VM::AUDIO, {25, VM::audio}},
            {VM::DISPLAY, {25, VM::display}},
            {VM::VIRTUAL_REGISTRY, {90, VM::virtual_registry}},
            {VM::MUTEX, {100, VM::mutex}},
            {VM::VPC_INVALID, {75, VM::vpc_invalid}},
            {VM::VMWARE_STR, {35, VM::vmware_str}},
            {VM::GAMARUE, {30, VM::gamarue}},
            {VM::CUCKOO, {30, VM::cuckoo}},
        #endif

        #if (VMAWARE_LINUX || VMAWARE_WINDOWS)
            {VM::FIRMWARE, {100, VM::firmware}},
            {VM::DEVICES, {95, VM::pci_devices}},
            {VM::SYSTEM_REGISTERS, {50, VM::system_registers}},
            {VM::AZURE, {30, VM::azure}},
            {VM::BOOT_LOGO, {90, VM::boot_logo}},
            {VM::DISK, {150, VM::disk}},
        #endif

        #if (VMAWARE_LINUX)
            {VM::SMBIOS_VM_BIT, {50, VM::smbios_vm_bit}},
            {VM::KMSG, {5, VM::kmsg}},
            {VM::CVENDOR, {65, VM::chassis_vendor}},
            {VM::QEMU_FW_CFG, {70, VM::qemu_fw_cfg}},
            {VM::SYSTEMD, {35, VM::systemd_virt}},
            {VM::CTYPE, {20, VM::chassis_type}},
            {VM::DOCKERENV, {100, VM::dockerenv}},
            {VM::DMIDECODE, {55, VM::dmidecode}},
            {VM::DMESG, {55, VM::dmesg}},
            {VM::HWMON, {35, VM::hwmon}},
            {VM::LINUX_USER_HOST, {10, VM::linux_user_host}},
            {VM::QEMU_VIRTUAL_DMI, {40, VM::qemu_virtual_dmi}},
            {VM::QEMU_USB, {20, VM::qemu_usb}},
            {VM::HYPERVISOR_DIR, {20, VM::hypervisor_dir}},
            {VM::UML_CPU, {80, VM::uml_cpu}},
            {VM::VBOX_MODULE, {15, VM::vbox_module}},
            {VM::SYSINFO_PROC, {15, VM::sysinfo_proc}},
            {VM::DMI_SCAN, {50, VM::dmi_scan}},
            {VM::PODMAN_FILE, {5, VM::podman_file}},
            {VM::WSL_PROC, {30, VM::wsl_proc_subdir}},
            {VM::FILE_ACCESS_HISTORY, {15, VM::file_access_history}},
            {VM::MAC, {20, VM::mac_address_check}},
            {VM::CONTAINER_PID, {75, VM::container_proc_id}},
            {VM::BLUESTACKS_FOLDERS, {5, VM::bluestacks}},
            {VM::AMD_SEV_MSR, {50, VM::amd_sev_msr}},
            {VM::TEMPERATURE, {20, VM::temperature}},
            {VM::CGROUP, {70, VM::cgroup}},
            {VM::PROCESSES, {40, VM::processes}},
        #endif    

        #if (VMAWARE_LINUX || VMAWARE_APPLE)
            {VM::THREAD_COUNT, {35, VM::thread_count}},
        #endif

        #if (VMAWARE_APPLE)
            {VM::MAC_MEMSIZE, {15, VM::hw_memsize}},
            {VM::MAC_IOKIT, {100, VM::io_kit}},
            {VM::MAC_SIP, {100, VM::mac_sip}},
            {VM::IOREG_GREP, {100, VM::ioreg_grep}},
            {VM::HWMODEL, {100, VM::hwmodel}},
            {VM::MAC_SYS, {100, VM::mac_sys}},
        #endif

        {VM::TIMER, {100, VM::timer}},
        {VM::THREAD_MISMATCH, {45, VM::thread_mismatch}},
        {VM::VMID, {100, VM::vmid}},
        {VM::CPU_BRAND, {95, VM::cpu_brand}},
        {VM::CPUID_SIGNATURE, {95, VM::cpuid_signature}},
        {VM::HYPERVISOR_STR, {150, VM::hypervisor_str}},
        {VM::HYPERVISOR_BIT, {150, VM::hypervisor_bit}},
        {VM::BOCHS_CPU, {100, VM::bochs_cpu}},
        {VM::KGT_SIGNATURE, {80, VM::intel_kgt_signature}}
        /* END OF TECHNIQUE TABLE */
    };

    /* Fill the table based on ID */
    for (const auto& entry : entries) {
        if (entry.id < table.size()) {
            table.at(entry.id) = entry.tech;
        }
    }
    return table;
}();

static_assert(VM::core::technique_table.size() == VM::enum_size + 1, "technique_table must map to every enum value.");

#undef debug

#endif /* VMAWARE_HEADER */