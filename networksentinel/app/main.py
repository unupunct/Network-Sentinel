"""Network Sentinel application entry point."""

from __future__ import annotations

import argparse
import logging
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from networksentinel import APP_NAME, APP_VERSION
from networksentinel.core.logging import get_logger, setup_logging
from networksentinel.core.paths import log_dir
from networksentinel.ui.theme import stylesheet
from networksentinel.widgets.common import app_icon

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-sentinel", description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    parser.add_argument("--selftest", action="store_true",
                        help="run headless service checks and exit")
    parser.add_argument("--screenshots", metavar="DIR",
                        help="render every page to PNG in DIR and exit (used for the docs)")
    parser.add_argument("--no-monitor", action="store_true",
                        help="start the GUI without the background monitoring loop")
    return parser


def run_selftest() -> int:
    from networksentinel.app.context import build_context

    setup_logging(logging.INFO)
    try:
        context = build_context()
        print(f"{APP_NAME} {APP_VERSION} self-test")
        print(f"  data directory     : {context.db.path.parent}")
        iface = context.interface
        print(f"  interface          : {iface.name if iface else 'none'} "
              f"{iface.ipv4 if iface else ''} {iface.cidr if iface else ''}")
        print(f"  privileges         : admin={context.interfaces.privileges['is_admin']} "
              f"raw_capture={context.interfaces.privileges['raw_capture']}")
        context.discovery.scan(iface.name if iface else None)
        context.inventory.sync()
        devices = context.inventory.all_devices()
        print(f"  devices discovered : {len(devices)}")
        for device in devices[:8]:
            print(f"    - {device.name:<24} {device.ip or '':<16} {device.mac} "
                  f"{(device.vendor or 'unknown vendor')[:26]:<26} {device.device_type}")
        context.explorer.poll_local(iface.ipv4 if iface else None)
        stats = context.explorer.stats()
        print(f"  connections        : {stats['total']} tracked ({stats['active']} active)")
        context.bandwidth.sample(iface.name if iface else None)
        summary = context.bandwidth.summary()
        print(f"  bandwidth          : down {summary['download_bps']} up {summary['upload_bps']}")
        result = context.security.run()
        print(f"  security findings  : {context.security.stats()['findings']} "
              f"(created {result.get('created', 0)} this run)")
        path = context.reports.generate("pdf", 3600)
        print(f"  report             : {path}")
        print("  result             : OK")
        context.shutdown()
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"self-test failed: {exc}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_file = setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    if args.selftest:
        return run_selftest()

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("Network Sentinel Project")
    app.setWindowIcon(app_icon())
    app.setStyleSheet(stylesheet())
    setattr(app, "_sentinel_icon", app_icon())

    from networksentinel.app.context import build_context

    log.info("Starting %s %s (log: %s)", APP_NAME, APP_VERSION, log_file)
    try:
        context = build_context()
    except Exception as exc:
        QMessageBox.critical(None, f"{APP_NAME} could not start",
                             f"Startup failed:\n\n{exc}\n\nSee {log_dir()}")
        return 1

    from networksentinel.ui.main_window import MainWindow

    window = MainWindow(context)
    window.show()
    if args.screenshots:
        from networksentinel.ui.screenshots import capture_all

        context.start()
        QApplication.processEvents()
        capture_all(window, args.screenshots)
        context.shutdown()
        return 0
    if not args.no_monitor and not context.monitoring:
        context.start()
    code = app.exec()
    context.shutdown()
    return code


if __name__ == "__main__":
    sys.exit(main())
