#[cfg(feature = "static-fallback")]
fn build() {
    use std::collections::HashSet;
    use std::env;
    use std::path::Path;

    let src = Path::new("Picnic");
    let target = env::var("TARGET").unwrap();
    let profile = env::var("PROFILE").unwrap();
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
        .map(|s| s.parse::<u32>().unwrap_or(64))
        .unwrap();
    let target_cpu = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let mut build = cc::Build::new();
    build.static_flag(true);
    build.flag_if_supported("-std=gnu11");
    build.flag_if_supported("-fstack-protector-strong");
    build.define("_FORTIFY_SOURCE", Some("2"));
    build.define("WITHOUT_BUILTIN_CPU_SUPPORTS", None);
    build.define("PICNIC_STATIC", None);
    build.define("NDEBUG", None);
    build.define("WITH_KECCAK_X4", None);
    if target_cpu.starts_with("arm") && pointer_width == 32 {
        // 32 bit ARM is in general unhappy with unaligned access
        build.define("NO_MISALIGNED_ACCESSES", None);
    }
    build.include(src);
    build.include(src.join("sha3"));
    if pointer_width == 32 {
        build.include(src.join("sha3/plain32"));
    } else {
        build.include(src.join("sha3/opt64"));
    }
    if profile == "release" {
        build.opt_level(3);
    }

    if target_cpu == "x86" || target_cpu == "x86_64" {
        build.define("WITH_OPT", None);
        build.define("WITH_SSE2", None);
        if target_cpu == "x86_64" {
            build.define("WITH_AVX2", None);
        }
    }
    if target_cpu == "aarch64" {
        build.define("WITH_OPT", None);
        build.define("WITH_NEON", None);
    }

    let mut files: HashSet<&str> = HashSet::new();
    files.extend(
        [
            "compat.c",
            "cpu.c",
            "io.c",
            "picnic.c",
            "picnic_instances.c",
            "randomness.c",
            "lowmc.c",
            "mzd_additional.c",
            "sha3/KeccakHash.c",
            "sha3/KeccakSponge.c",
            "sha3/KeccakSpongetimes4.c",
            "sha3/KeccakHashtimes4.c",
        ]
        .iter(),
    );
    if pointer_width == 32 {
        files.extend(
            [
                "sha3/plain32/KeccakP-1600-inplace32BI.c",
                "sha3/plain32/KeccakP-1600-times4-on1.c",
            ]
            .iter(),
        );
    } else {
        files.extend(
            [
                "sha3/opt64/KeccakP-1600-opt64.c",
                "sha3/opt64/KeccakP-1600-times4-on1.c",
            ]
            .iter(),
        );
    }

    if cfg!(feature = "picnic") {
        files.extend(
            [
                "picnic_impl.c",
                "mpc_lowmc.c",
                "lowmc_128_128_20.c",
                "lowmc_129_129_4.c",
                "lowmc_192_192_30.c",
                "lowmc_192_192_4.c",
                "lowmc_255_255_4.c",
                "lowmc_256_256_38.c",
            ]
            .iter(),
        );
        if cfg!(feature = "param-bindings") {
            files.extend(
                [
                    "picnic_L1_FS/picnic_l1_fs.c",
                    "picnic_L3_FS/picnic_l3_fs.c",
                    "picnic_L5_FS/picnic_l5_fs.c",
                    "picnic_L1_full/picnic_l1_full.c",
                    "picnic_L3_full/picnic_l3_full.c",
                    "picnic_L5_full/picnic_l5_full.c",
                ]
                .iter(),
            );
        }
        build.define("WITH_ZKBPP", None);
        build.define("WITH_LOWMC_128_128_20", None);
        build.define("WITH_LOWMC_192_192_30", None);
        build.define("WITH_LOWMC_256_256_38", None);
        build.define("WITH_LOWMC_129_129_4", None);
        build.define("WITH_LOWMC_192_192_4", None);
        build.define("WITH_LOWMC_255_255_4", None);
        if cfg!(feature = "unruh-transform") {
            build.define("WITH_UNRUH", None);
            if cfg!(feature = "param-bindings") {
                files.extend(
                    [
                        "picnic_L1_UR/picnic_l1_ur.c",
                        "picnic_L3_UR/picnic_l3_ur.c",
                        "picnic_L5_UR/picnic_l5_ur.c",
                    ]
                    .iter(),
                );
            }
        }
    }

    if cfg!(feature = "picnic3") {
        files.extend(
            [
                "picnic3_impl.c",
                "picnic3_simulate.c",
                "picnic3_types.c",
                "picnic3_tree.c",
                "lowmc_192_192_4.c",
                "lowmc_255_255_4.c",
                "lowmc_256_256_38.c",
            ]
            .iter(),
        );
        if cfg!(feature = "param-bindings") {
            files.extend(
                [
                    "picnic3_L1/picnic3_l1.c",
                    "picnic3_L3/picnic3_l3.c",
                    "picnic3_L5/picnic3_l5.c",
                ]
                .iter(),
            );
        }
        build.define("WITH_KKW", None);
        build.define("WITH_LOWMC_129_129_4", None);
        build.define("WITH_LOWMC_192_192_4", None);
        build.define("WITH_LOWMC_255_255_4", None);
    }

    build
        .files(files.iter().map(|v| src.join(v)))
        .compile("picnic");

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
    }
}

fn main() {
    #[cfg(feature = "system")]
    {
        #[cfg(feature = "param-bindings")]
        let version_range = "3.0.18".."4.0";
        #[cfg(not(feature = "param-bindings"))]
        let version_range = "3.0.5".."4.0";

        // Try to find shared library via pkg-config
        if pkg_config::Config::new()
            .range_version(version_range)
            .probe("picnic")
            .is_ok()
        {
            return;
        }
    }

    #[cfg(feature = "static-fallback")]
    // Download and build static library
    build();
    #[cfg(not(feature = "static-fallback"))]
    panic!("Unable to find library with pkg-config and static-fallback is not enabled!")
}
