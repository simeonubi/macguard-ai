from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.safety.canonicalizer import canonicalize_path, is_contained_within
from app.safety.path_validator import Operation, PathValidator


def test_path_fuzzing_traversal_and_malformed_inputs() -> None:
    """Fuzz canonicalization and validation with various adversarial path constructions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = Path(tmpdir).resolve()
        cache_dir = sandbox / "Library" / "Caches" / "com.apple.test"
        cache_dir.mkdir(parents=True)

        fuzz_cases = [
            # Traversal patterns
            f"{cache_dir}/../..",
            f"{cache_dir}/../../../System",
            f"{cache_dir}/./././../Caches",
            f"{cache_dir}//subdir///file",
            f"{cache_dir}/subdir/.",
            f"{cache_dir}/subdir/..",
            f"{cache_dir}/trailing_slash/",
            # Unicode and spaces
            f"{cache_dir}/unicode_\u00e9\u00e0\u00ee_test",
            f"{cache_dir}/path with multiple spaces /file.log",
            # Very long path (250 chars)
            f"{cache_dir}/" + "a" * 200 + "/test.cache",
            # Prefix collision attempts
            f"{cache_dir}-evil",
            f"{cache_dir}_malicious/payload",
            # Null bytes (should raise ValueError)
            f"{cache_dir}\x00malicious",
        ]

        validator = PathValidator()

        for case in fuzz_cases:
            if "\x00" in case:
                with pytest.raises(ValueError):
                    canonicalize_path(case)
                continue

            canon = canonicalize_path(case)
            assert canon.path_str is not None

            # PathValidator must never crash on fuzzed input
            result = validator.validate_path(canon.path_str, operation=Operation.CLEAN)
            assert isinstance(result.allowed, bool)
            assert result.canonical_path == canon.path_str


def test_symlink_fuzzing_and_circular_detection() -> None:
    """Verify that circular or escaping symlinks are handled safely without infinite recursion."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = Path(tmpdir).resolve()
        link_a = sandbox / "link_a"
        link_b = sandbox / "link_b"

        try:
            link_a.symlink_to(link_b)
            link_b.symlink_to(link_a)
        except OSError:
            pytest.skip("Symlink creation not permitted in this environment")

        # Resolving circular symlink must safely resolve without infinite recursion
        canon = canonicalize_path(str(link_a))
        assert canon is not None
        assert isinstance(canon.is_symlink, bool)
