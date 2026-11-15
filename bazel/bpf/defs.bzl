"""Compiles a CO-RE eBPF program with the hermetic clang of @llvm_toolchain_llvm.

The compiler is the LLVM release toolchains_llvm downloads for the machine
Bazel runs on (linux amd64 or arm64), with its BPF backend. Nothing on the host
is used: not clang, not the kernel headers, not a vmlinux.h.
"""

def _bpf_object_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.out)
    srcs = ctx.files.src
    if len(srcs) != 1:
        fail("bpf_object %s: src must be one file" % ctx.label)

    # Quote includes: the program's own directory. System includes: libbpf's
    # src/ (bpf_helpers.h, bpf_core_read.h, bpf_tracing.h).
    includes = {}
    for f in ctx.files.hdrs:
        includes[f.dirname] = True
    system = {}
    for f in ctx.files.libbpf_hdrs:
        if f.basename == "bpf_helpers.h":
            system[f.dirname] = True
    if len(system) != 1:
        fail("bpf_object %s: libbpf_hdrs must hold exactly one bpf_helpers.h" % ctx.label)

    args = ctx.actions.args()
    args.add("--target=bpfel")
    args.add("-mcpu=" + ctx.attr.cpu)
    args.add("-O2")
    args.add("-g")  # BTF: CO-RE relocations and the maps' definitions
    args.add("-Wall")
    args.add("-Werror")
    args.add("-nostdinc")
    args.add("-fno-stack-protector")

    # Reproducible: no host path or date in the object's debug info.
    args.add("-fdebug-compilation-dir=.")
    args.add("-ffile-prefix-map=" + srcs[0].dirname + "=.")
    args.add_all(includes.keys(), before_each = "-iquote")
    args.add_all(system.keys(), before_each = "-isystem")
    args.add("-c")
    args.add(srcs[0])
    args.add("-o")
    args.add(out)

    ctx.actions.run(
        executable = ctx.executable.clang,
        arguments = [args],
        inputs = depset(srcs + ctx.files.hdrs + ctx.files.libbpf_hdrs, transitive = [ctx.attr.clang_runtime[DefaultInfo].files]),
        outputs = [out],
        mnemonic = "BpfCompile",
        progress_message = "Compiling BPF object %s" % out.short_path,
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([out]))]

bpf_object = rule(
    implementation = _bpf_object_impl,
    attrs = {
        "clang": attr.label(
            doc = "The clang binary.",
            default = "@llvm_toolchain_llvm//:bin/clang",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "clang_runtime": attr.label(
            doc = "What clang needs next to it: its resource directory.",
            default = "@llvm_toolchain_llvm//:lib",
            cfg = "exec",
        ),
        "cpu": attr.string(
            doc = "The BPF instruction set: v3 needs Linux 5.1.",
            default = "v3",
        ),
        "hdrs": attr.label_list(allow_files = [".h"], doc = "Headers of the program."),
        "libbpf_hdrs": attr.label(
            doc = "libbpf's headers (its src/ directory).",
            default = "@libbpf//:source_headers",
            allow_files = True,
        ),
        "out": attr.string(mandatory = True),
        "src": attr.label(allow_single_file = [".c"], mandatory = True),
    },
    doc = "Compiles one CO-RE eBPF C file to a little-endian BPF object.",
)
