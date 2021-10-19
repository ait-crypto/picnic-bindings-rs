#[cfg(feature = "static-fallback")]
fn download_and_build() {
    let download = librarian::download_or_find_file(
        "https://github.com/IAIK/Picnic/archive/refs/tags/v3.0.4.tar.gz",
        None,
    )
    .expect("Failed to download Picnic");

    let src = librarian::extract_archive(&download, None)
        .expect("Failed to extract Picnic source")
        .join("Picnic-3.0.4");

    let mut build = cc::Build::new();
    build.static_flag(true);
    build.define("PICNIC_STATIC", None);
    build.include(src.join("sha3"));
    build.include(src.join("sha3/opt64"));
    match std::env::var("PROFILE") {
        Ok(v) => {
            if v == "release" {
                build.opt_level(3);
            }
        }
        _ => {}
    }

    if cfg!(target_feature = "sse2") {
        build.define("WITH_OPT", None);
        build.define("WITH_SSE2", None);
        if cfg!(target_feature = "avx2") && cfg!(target_feature = "bmi2") {
            build.define("WITH_AVX2", None);
        }
    }
    if cfg!(target_feature = "neon") {
        build.define("WITH_SIMD_OPT", None);
        build.define("WITH_NEON", None);
    }

    let mut files = std::collections::HashSet::from([
        "bitstream.c",
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
        "sha3/opt64/KeccakP-1600-opt64.c",
        "sha3/opt64/KeccakP-1600-times4-on1.c",
    ]);

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
        build.define("WITH_ZKBPP", None);
        build.define("WITH_LOWMC_128_128_20", None);
        build.define("WITH_LOWMC_192_192_30", None);
        build.define("WITH_LOWMC_256_256_38", None);
        build.define("WITH_LOWMC_129_129_4", None);
        build.define("WITH_LOWMC_192_192_4", None);
        build.define("WITH_LOWMC_255_255_4", None);
        #[cfg(feature = "unruh-transform")]
        build.define("WITH_UNRUH", None);
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
        build.define("WITH_KKW", None);
        build.define("WITH_LOWMC_129_129_4", None);
        build.define("WITH_LOWMC_192_192_4", None);
        build.define("WITH_LOWMC_255_255_4", None);
    }

    build
        .files(files.iter().map(|v| src.join(v)))
        .compile("picnic");
}

fn main() {
    #[cfg(feature = "system")]
    // Try to find shared library via pkg-config
    if pkg_config::Config::new()
        .range_version("3.0".."4.0")
        .probe("picnic")
        .is_ok()
    {
        return;
    }

    #[cfg(feature = "static-fallback")]
    // Download and build static library
    download_and_build();
    #[cfg(not(feature = "static-fallback"))]
    panic!("Unable to find library with pkg-config and static-fallback is not enabled!")
}
