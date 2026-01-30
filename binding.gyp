{
  "targets": [
    {
      "target_name": "capstone_native",
      "sources": [
        "src/main.cpp",
        "src/capstone_wrapper.cpp",

        "deps/capstone/cs.c",
        "deps/capstone/MCInst.c",
        "deps/capstone/MCInstrDesc.c",
        "deps/capstone/MCRegisterInfo.c",
        "deps/capstone/Mapping.c",
        "deps/capstone/SStream.c",
        "deps/capstone/utils.c",

        "deps/capstone/arch/X86/X86Module.c",
        "deps/capstone/arch/X86/X86Disassembler.c",
        "deps/capstone/arch/X86/X86DisassemblerDecoder.c",
        "deps/capstone/arch/X86/X86ATTInstPrinter.c",
        "deps/capstone/arch/X86/X86IntelInstPrinter.c",
        "deps/capstone/arch/X86/X86InstPrinterCommon.c",
        "deps/capstone/arch/X86/X86Mapping.c",

        "deps/capstone/arch/ARM/ARMModule.c",
        "deps/capstone/arch/ARM/ARMDisassembler.c",
        "deps/capstone/arch/ARM/ARMInstPrinter.c",
        "deps/capstone/arch/ARM/ARMMapping.c",

        "deps/capstone/arch/AArch64/AArch64Module.c",
        "deps/capstone/arch/AArch64/AArch64Disassembler.c",
        "deps/capstone/arch/AArch64/AArch64InstPrinter.c",
        "deps/capstone/arch/AArch64/AArch64Mapping.c",
        "deps/capstone/arch/AArch64/AArch64BaseInfo.c",

        "deps/capstone/arch/Mips/MipsModule.c",
        "deps/capstone/arch/Mips/MipsDisassembler.c",
        "deps/capstone/arch/Mips/MipsInstPrinter.c",
        "deps/capstone/arch/Mips/MipsMapping.c",

        "deps/capstone/arch/PowerPC/PPCModule.c",
        "deps/capstone/arch/PowerPC/PPCDisassembler.c",
        "deps/capstone/arch/PowerPC/PPCInstPrinter.c",
        "deps/capstone/arch/PowerPC/PPCMapping.c",

        "deps/capstone/arch/Sparc/SparcModule.c",
        "deps/capstone/arch/Sparc/SparcDisassembler.c",
        "deps/capstone/arch/Sparc/SparcInstPrinter.c",
        "deps/capstone/arch/Sparc/SparcMapping.c",

        "deps/capstone/arch/SystemZ/SystemZModule.c",
        "deps/capstone/arch/SystemZ/SystemZDisassembler.c",
        "deps/capstone/arch/SystemZ/SystemZInstPrinter.c",
        "deps/capstone/arch/SystemZ/SystemZMapping.c",
        "deps/capstone/arch/SystemZ/SystemZMCTargetDesc.c",

        "deps/capstone/arch/XCore/XCoreModule.c",
        "deps/capstone/arch/XCore/XCoreDisassembler.c",
        "deps/capstone/arch/XCore/XCoreInstPrinter.c",
        "deps/capstone/arch/XCore/XCoreMapping.c",

        "deps/capstone/arch/M68K/M68KModule.c",
        "deps/capstone/arch/M68K/M68KDisassembler.c",
        "deps/capstone/arch/M68K/M68KInstPrinter.c",

        "deps/capstone/arch/TMS320C64x/TMS320C64xModule.c",
        "deps/capstone/arch/TMS320C64x/TMS320C64xDisassembler.c",
        "deps/capstone/arch/TMS320C64x/TMS320C64xInstPrinter.c",
        "deps/capstone/arch/TMS320C64x/TMS320C64xMapping.c",

        "deps/capstone/arch/M680X/M680XModule.c",
        "deps/capstone/arch/M680X/M680XDisassembler.c",
        "deps/capstone/arch/M680X/M680XInstPrinter.c",

        "deps/capstone/arch/EVM/EVMModule.c",
        "deps/capstone/arch/EVM/EVMDisassembler.c",
        "deps/capstone/arch/EVM/EVMInstPrinter.c",
        "deps/capstone/arch/EVM/EVMMapping.c",

        "deps/capstone/arch/WASM/WASMModule.c",
        "deps/capstone/arch/WASM/WASMDisassembler.c",
        "deps/capstone/arch/WASM/WASMInstPrinter.c",
        "deps/capstone/arch/WASM/WASMMapping.c",

        "deps/capstone/arch/MOS65XX/MOS65XXModule.c",
        "deps/capstone/arch/MOS65XX/MOS65XXDisassembler.c",

        "deps/capstone/arch/BPF/BPFModule.c",
        "deps/capstone/arch/BPF/BPFDisassembler.c",
        "deps/capstone/arch/BPF/BPFInstPrinter.c",
        "deps/capstone/arch/BPF/BPFMapping.c",

        "deps/capstone/arch/RISCV/RISCVModule.c",
        "deps/capstone/arch/RISCV/RISCVDisassembler.c",
        "deps/capstone/arch/RISCV/RISCVInstPrinter.c",
        "deps/capstone/arch/RISCV/RISCVMapping.c",

        "deps/capstone/arch/SH/SHModule.c",
        "deps/capstone/arch/SH/SHDisassembler.c",
        "deps/capstone/arch/SH/SHInstPrinter.c",

        "deps/capstone/arch/TriCore/TriCoreModule.c",
        "deps/capstone/arch/TriCore/TriCoreDisassembler.c",
        "deps/capstone/arch/TriCore/TriCoreInstPrinter.c",
        "deps/capstone/arch/TriCore/TriCoreMapping.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/capstone/include",
        "deps/capstone"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "CAPSTONE_HAS_X86",
        "CAPSTONE_HAS_ARM",
        "CAPSTONE_HAS_ARM64",
        "CAPSTONE_HAS_MIPS",
        "CAPSTONE_HAS_POWERPC",
        "CAPSTONE_HAS_SPARC",
        "CAPSTONE_HAS_SYSZ",
        "CAPSTONE_HAS_XCORE",
        "CAPSTONE_HAS_M68K",
        "CAPSTONE_HAS_TMS320C64X",
        "CAPSTONE_HAS_M680X",
        "CAPSTONE_HAS_EVM",
        "CAPSTONE_HAS_WASM",
        "CAPSTONE_HAS_MOS65XX",
        "CAPSTONE_HAS_BPF",
        "CAPSTONE_HAS_RISCV",
        "CAPSTONE_HAS_SH",
        "CAPSTONE_HAS_TRICORE",
        "CAPSTONE_USE_SYS_DYN_MEM"
      ],
      "conditions": [
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalIncludeDirectories": [
                "<(module_root_dir)/deps/capstone/include",
                "<(module_root_dir)/deps/capstone"
              ],
              "DisableSpecificWarnings": ["4244", "4267", "4996"]
            }
          },
          "defines": [
            "WIN32",
            "_WINDOWS"
          ]
        }],
        ["OS=='linux'", {
          "cflags": ["-fPIC", "-w"],
          "cflags_cc": ["-fPIC", "-std=c++17", "-w"]
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "10.15",
            "WARNING_CFLAGS": ["-w"],
            "OTHER_CFLAGS": ["-w"]
          }
        }]
      ]
    }
  ]
}
