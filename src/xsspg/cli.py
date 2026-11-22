"""Command-line entry point for XSS-PG."""

import argparse
from getpass import getpass

from .browser_test import run_reflected_xss_test
from .payloads import PayloadProfile, generate_payload
from .security import DEFAULT_TARGET, ScopeError, normalize_local_target, require_authorization
from .target import check_dvwa


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="xss-pg",
        description="Generate and verify a harmless Reflected XSS proof-of-execution in a local DVWA lab.",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Local DVWA base URL (default: %(default)s)")
    parser.add_argument("--headless", action="store_true", help="Run Chromium without a visible browser window")
    return parser.parse_args()


def _operator_checkpoint(message: str) -> None:
    """Require explicit operator acknowledgement before the next test stage."""
    print(f"\n[OPERATOR CHECKPOINT] {message}")
    input("Press ENTER to continue, or Ctrl+C to abort: ")


def _run() -> int:
    args = parse_args()
    if not require_authorization():
        print("Authorization not confirmed. Exiting without testing.")
        return 1

    try:
        target = normalize_local_target(args.target)
    except ScopeError as exc:
        print(f"[SCOPE BLOCKED] {exc}")
        return 2

    print(f"\n[+] Authorized local target: {target}")
    identified, message = check_dvwa(target)
    print(f"[{'+' if identified else '!'}] {message}")
    if not identified:
        return 3

    while True:
        print("\nXSS PAYLOAD GENERATOR & TESTER — DVWA")
        print("[1] Generate Reflected XSS proof-of-concept")
        print("[2] Test DVWA Reflected XSS (Low; operator checkpoints)")
        print("[Q] Quit")
        choice = input("Select: ").strip().lower()

        if choice == "1":
            generated = generate_payload(PayloadProfile.REFLECTED)
            print(f"\nProfile: {generated.profile.value}")
            print(f"Parameter: {generated.parameter}")
            print(f"Description: {generated.description}")
            print(f"Payload: {generated.value}")
        elif choice == "2":
            username = input("DVWA username [admin]: ").strip() or "admin"
            password = getpass("DVWA password [press Enter for default 'password']: ")
            password = password or "password"
            generated = generate_payload(PayloadProfile.REFLECTED)
            print("\n[*] Starting local Chromium test. Credentials are used only for this DVWA session.")
            result = run_reflected_xss_test(
                target,
                generated.value,
                username,
                password,
                headless=args.headless,
                progress_callback=print,
                checkpoint_callback=_operator_checkpoint,
                pause_for_alert=not args.headless,
            )
            print(result.message)
            print(f"Target: {result.target}")
            if result.security_level is not None:
                print(f"Security level: {result.security_level}")
        elif choice in {"q", "quit", "exit"}:
            print("Exiting cleanly.")
            return 0
        else:
            print("Invalid selection. Choose 1, 2, or Q.")


def main() -> int:
    """Run the CLI and translate Ctrl+C into a clean exit code."""
    try:
        return _run()
    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user. Exiting cleanly.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
